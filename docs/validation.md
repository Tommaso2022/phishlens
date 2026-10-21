# Validazione e limiti — PhishLens

Riferimenti: ASVS v5.0.0 capitoli V1 e V2 · Threat model: AC1, AC2, AC3, AC7, AC8, AC9

Principi:

1. **Validazione positiva:** si definisce cosa è accettato; tutto il resto è rifiutato.
2. **Nel backend:** gli schemi Pydantic strict sono l'unico controllo che conta; il frontend valida solo per comodità.
3. **Normalizzare una volta, poi validare:** l'input viene portato alla forma canonica all'ingresso e da lì in poi si usa solo quella.
4. **Campi sconosciuti rifiutati:** `extra="forbid"` su ogni schema di input.

I valori numerici sono la configurazione di partenza: se cambiano nel codice, va aggiornato questo documento.

## 1. Regole per ogni tipo di dato

| Dato | Regola |
| --- | --- |
| URL da analizzare | Massimo 2048 caratteri dopo la normalizzazione; schema `http` o `https`; host obbligatorio; nessuna credenziale nell'URL (`utente:password@`); dominio internazionale convertito in punycode; porta assente, 80 o 443 |
| Dominio (controllo blocklist) | Nome di dominio valido secondo le regole DNS, massimo 253 caratteri, convertito in punycode e in minuscolo |
| Email | Formato verificato con `email-validator`, massimo 254 caratteri, dominio in minuscolo |
| Password | Regole di `docs/authentication.md`, sezione 2 |
| Codice TOTP | Esattamente 6 cifre |
| Codice di recupero | 16 caratteri dell'alfabeto base32, trattini ignorati |
| ID di risorse | UUID valido; altrimenti 404 |
| Paginazione | `limit` da 1 a 50, `offset` da 0 a 10.000 |
| File `.eml` (Fase 5) | Massimo 10 MB, massimo 100 parti MIME, annidamento massimo 5 livelli |

## 2. Coerenza tra dati combinati

| Operazione | Controllo |
| --- | --- |
| Confronto tra due analisi | Entrambe appartengono all'utente e riguardano lo stesso URL normalizzato |
| Cambio password | La nuova password è diversa da quella attuale |
| Cambio email | La nuova email è diversa dall'attuale e non è già registrata; diventa effettiva solo dopo la verifica |
| Reset della password | Il token appartiene all'utente indicato, non è scaduto e non è stato usato |
| Login a due passi | Il secondo fattore è inviato con la sessione parziale nata dal primo passo |

## 3. Limiti di business

### Per utente

| Limite | Valore |
| --- | --- |
| Analisi | 50 al giorno |
| Analisi in coda contemporaneamente | 5 |
| Analisi dello stesso dominio registrato | 20 all'ora (contro l'uso come oracolo, AC9) |
| Cambi di email | 3 al giorno |
| Esportazioni dei dati | 3 al giorno |

### Per tutta l'applicazione

| Limite | Valore |
| --- | --- |
| Richieste del fetcher verso lo stesso dominio di destinazione | 30 all'ora, da tutti gli utenti insieme (contro l'uso come proxy, AC8) |
| Budget giornaliero per ogni API esterna | 80% della quota del piano gratuito; oltre, analisi parziale |
| Lunghezza della coda | 500 job; oltre, nuove analisi rifiutate con messaggio di servizio occupato |
| Registrazioni | 5 al giorno per IP; i limiti di login sono in `docs/authentication.md`, sezione 3 |

Il consumo dei limiti avviene con operazioni atomiche: richieste parallele non devono poter superare la quota (ASVS 2.3.4).

## 4. Validazione degli URL prima di una connessione (anti-SSRF)

Un analizzatore deve poter visitare qualunque sito pubblico, quindi una allowlist di domini, come suggerisce ASVS 1.3.6, è impossibile. È una deviazione documentata: al suo posto si usano questi controlli, tutti nel fetcher.

1. Schema `http` o `https`, porta 80 o 443.
2. Risoluzione DNS: rifiuto se **anche uno solo** degli indirizzi non è pubblico (loopback, privati, link-local, multicast, riservati, IPv6 ULA, IPv4 mappati in IPv6).
3. Connessione all'IP appena verificato (IP pinning), con Host e SNI impostati a mano.
4. Massimo 5 redirect, ognuno rivalidato dal punto 1.
5. Timeout totale 10 secondi, risposta massima 2 MB, nessun cookie e nessun header scelto dall'utente.
6. Un solo parser di URL in tutta l'applicazione (ASVS 1.5.3): l'oggetto normalizzato all'ingresso è lo stesso usato dal client HTTP.
7. Isolamento di rete del fetcher, come seconda barriera indipendente.

Le chiamate del worker verso le API esterne usano invece una allowlist esplicita di domini, configurata anche a livello di rete.
