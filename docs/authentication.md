# Autenticazione — PhishLens

Riferimenti: ASVS v5.0.0 capitolo V6 · ADR-002 (sessioni lato server), ADR-003 (MFA obbligatoria) · Threat model: S-01, AC1, AC10

I valori numerici sono la configurazione di partenza: se cambiano nel codice, va aggiornato questo documento.

## 1. Percorsi di autenticazione

Non esistono altri modi per ottenere una sessione. Ogni percorso richiede gli stessi due fattori: qualcosa che l'utente sa (password) e qualcosa che ha (app TOTP o codice di recupero).

| Percorso | Passi | Fattori richiesti |
| --- | --- | --- |
| Login | `POST /auth/login` (email + password) → `POST /auth/login/totp` (codice TOTP) | Password + TOTP |
| Login con codice di recupero | `POST /auth/login` → `POST /auth/login/recovery` (codice monouso) | Password + codice di recupero |
| Reset della password | `POST /auth/password-reset/request` → link via email → `POST /auth/password-reset/confirm` (nuova password + TOTP) | Possesso dell'email + TOTP; poi un login normale |

Dopo il primo fattore la sessione è "parziale": dà accesso solo all'endpoint del secondo fattore e scade dopo 5 minuti. La sessione completa nasce solo dopo il secondo fattore.

Alla registrazione l'utente verifica l'email e poi deve configurare il TOTP prima di poter usare qualunque altra funzione (ADR-003).

Non sono previsti login con provider esterni (OAuth/OIDC), SMS, notifiche push, domande segrete o "magic link" via email.

## 2. Policy delle password

| Regola | Valore |
| --- | --- |
| Lunghezza minima | 15 caratteri |
| Lunghezza massima | 128 caratteri, per limitare il costo dell'hashing (DoS) |
| Regole di composizione | Nessuna: qualunque carattere è consentito |
| Trasformazioni | Nessuna: niente trim, troncamento o cambio di maiuscole |
| Scadenza periodica | Nessuna; cambio richiesto solo se la password risulta compromessa |
| Password comuni | Rifiutate se presenti in `auth/data/common-passwords.txt` |
| Password violate | Rifiutate se presenti in Pwned Passwords (HIBP), tramite k-anonymity |
| Parole del contesto | Rifiutate se contengono una parola della sezione 2.1 |
| Hashing | Argon2id con i parametri raccomandati dalla libreria |

**Se HIBP non risponde**, la password viene accettata dopo i controlli locali e l'evento è registrato nel log. È un rischio residuo accettato: bloccare le registrazioni quando un servizio esterno è irraggiungibile sarebbe peggio.

### 2.1 Parole vietate

Il controllo ignora maiuscole e minuscole e rifiuta le password che **contengono** una di queste parole, anche con sostituzioni comuni (`0` per `o`, `1` per `i`, `3` per `e`, `4` o `@` per `a`, `5` o `$` per `s`):

`phishlens`, `phish`, `lens`, `phishing`, `password`, `admin`, `root`, `login`, la parte locale dell'email dell'utente (prima di `@`).

## 3. Difese contro attacchi automatizzati

Obiettivo: fermare credential stuffing e brute force **senza** permettere a un attaccante di bloccare l'account di qualcun altro.

| Controllo | Configurazione |
| --- | --- |
| Per coppia account + IP | Dopo 5 tentativi falliti, ritardo che raddoppia a ogni errore (1 s, 2 s, 4 s...) fino a 15 minuti |
| Per IP, su tutti gli account | Massimo 30 tentativi di login ogni 15 minuti |
| Per account, da tutti gli IP | Oltre 50 errori all'ora: avviso nell'audit log, nessun blocco |
| Secondo fattore | Massimo 5 codici errati per sessione parziale, poi la sessione parziale viene annullata |
| Reset e verifica email | Massimo 3 richieste all'ora per account e 10 per IP |
| Registrazione | Massimo 5 registrazioni al giorno per IP |
| Messaggi di errore | Sempre generici ("credenziali non valide"), con tempi di risposta simili |

**Perché nessun blocco permanente dell'account:** se dopo N errori l'account venisse bloccato, chiunque conosca l'email di un utente potrebbe impedirgli di entrare. Il ritardo legato alla coppia account + IP rallenta l'attaccante senza toccare l'utente legittimo, che si collega da un altro IP.

I contatori sono su Redis, con scadenza automatica. L'IP considerato è quello visto da Caddy (threat model, S-04).

## 4. TOTP

- Segreto generato con `pyotp.random_base32()`, salvato cifrato con una chiave esterna al database (threat model, I-03).
- Passo di 30 secondi. Si accetta l'intervallo corrente e un solo intervallo precedente, per tollerare lo sfasamento dell'orologio del telefono. È una deviazione documentata rispetto al limite di 30 secondi di ASVS 6.5.5.
- L'ultimo intervallo accettato è salvato per utente: lo stesso codice non può essere usato due volte.
- L'orario di riferimento è quello del server, sincronizzato via NTP.

## 5. Recupero

**Codici di recupero.** Alla configurazione del TOTP l'utente riceve 10 codici monouso da 16 caratteri base32 (80 bit), mostrati una sola volta e salvati con Argon2id. Può rigenerarli dopo aver confermato password e TOTP.

**Password dimenticata.** Si usa il percorso di reset della sezione 1. Il token è generato con `secrets.token_urlsafe(32)`, vale 10 minuti, è monouso, e una nuova richiesta invalida quelle precedenti. Il reset richiede comunque il TOTP e revoca tutte le sessioni attive.

**TOTP e codici di recupero persi.** L'utente scrive dall'indirizzo email dell'account. L'amministratore invia un link di verifica a quell'indirizzo; dopo la conferma l'utente deve inserire la password attuale. Solo allora l'amministratore esegue `phishlens-admin user reset-mfa` e l'utente riconfigura il TOTP al login successivo. Sono le stesse prove della registrazione: possesso dell'email e conoscenza della password. L'operazione è registrata nell'audit log.

## 6. Token generati dal sistema

| Token | Generazione | Validità | Uso |
| --- | --- | --- | --- |
| Verifica email | `secrets.token_urlsafe(32)` | 24 ore | Monouso |
| Reset password | `secrets.token_urlsafe(32)` | 10 minuti | Monouso; invalida i precedenti |
| ID di sessione | `secrets.token_urlsafe(32)` | Vedi ADR-002 | Salvato come hash |

Nessun token compare nei log. Il sistema non genera mai password per l'utente e non esistono account predefiniti.
