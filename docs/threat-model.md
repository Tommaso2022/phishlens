# Threat model — PhishLens

Versione: 0.1 · Ultimo aggiornamento: 2026-10-20 · Autore: Grandi Tommaso

## 1. Scopo e perimetro
PhishLens è una web app che analizza URL ed email sospette e restituisce uno score di rischio da 0 a 100, spiegando con tecniche di ML spiegabile (SHAP) quali caratteristiche hanno determinato il verdetto. È pensata per utenti privati che vogliono capire se un link è pericoloso prima di aprirlo.

**Nel perimetro (MVP):** analisi di URL, spiegazione del verdetto, controllo del dominio in blocklist pubbliche, storico personale delle analisi, gestione dell'account con MFA. Estensione successiva: analisi di file `.eml`.

**Fuori dal perimetro:** verifica della sicurezza del proprio sito, scansioni attive di sistemi terzi, account aziendali con più utenti e ruoli, pannello di amministrazione web.

L'app è uno strumento di supporto alla decisione: i verdetti sono probabilistici e non garantiscono che un URL sia sicuro.

## 2. Use case
<!-- La tabella UC1–UC7 con i criteri di accettazione. -->

## 3. Asset da proteggere

| ID | Asset | Perché è prezioso | Impatto se compromesso |
| --- | --- | --- | --- |
| A1 | Credenziali e sessioni degli utenti | Danno accesso allo storico e all'account | Alto |
| A2 | Chiavi delle API esterne | Hanno quote limitate; un furto permette abusi a mio nome | Medio |
| A3 | Contenuto delle email caricate | Contiene dati personali di terzi (GDPR) | Alto |
| A4 | Storico delle analisi | Rivela cosa un utente sta verificando e perché | Medio |
| A5 | Integrità del modello e dei verdetti | Un verdetto falsato può spingere un utente ad aprire un link di phishing | Alto |
| A6 | Disponibilità del servizio e quote API | Senza di esse l'app non funziona | Medio |
| A7 | Rete interna e infrastruttura | Un attaccante che vi accede può raggiungere database e segreti | Alto |
| A8 | Reputazione dell'IP e del dominio del server | Se l'app viene usata come proxy, l'IP finisce nelle blocklist e il provider può sospendere il server | Medio |

## 4. Attori e livelli di fiducia

| Attore | Livello di fiducia | Cosa può fare legittimamente |
| --- | --- | --- |
| Visitatore anonimo | Nessuno | Vedere la pagina pubblica, registrarsi, effettuare il login |
| Utente registrato | Limitato | Analizzare URL entro le quote, vedere e cancellare solo le proprie analisi, gestire il proprio account |
| Amministratore | Alto | Gestire server e deploy via SSH; amministrare l’app tramite CLI sul server (vedi ADR-001); non esiste un pannello di amministrazione web. |
| Attaccante esterno | Nessuno | Nulla: può agire come visitatore o come utente registrato |
| Contenuto analizzato (URL, pagine, email) | Ostile per definizione | Nulla: è un dato, non deve mai essere eseguito, visitato dal backend o reso come HTML |
| Servizi esterni (VirusTotal, URLScan, blocklist) | Parziale | Forniscono informazioni utili, ma le risposte vanno validate e possono contenere dati scelti da un attaccante |
| Feed di dati per l'addestramento | Parziale | Forniscono esempi di phishing, ma possono essere inquinati (poisoning) |

## 5. Architettura e flussi di dati

```mermaid
flowchart LR
  subgraph Z1["Internet · utenti (non fidato)"]
    U[Browser utente]
  end
  subgraph Z6["Accesso amministrativo"]
    A[Amministratore]
  end
  subgraph Z2["Rete app"]
    C[Caddy · TLS]
    B[Backend FastAPI]
    W[Worker ML]
  end
  subgraph Z3["Rete interna · senza Internet"]
    DB[(PostgreSQL)]
    R[(Redis)]
  end
  subgraph Z4["Rete egress"]
    F[Fetcher]
  end
  subgraph Z5["Internet · non fidato"]
    S[Siti analizzati]
    API[API esterne]
    BL[Blocklist]
  end

  U -- "F1 HTTPS" --> C
  C -- "F2" --> B
  B -- "F3 SQL" --> DB
  B -- "F4 job ID" --> R
  R -- "F5 job ID" --> W
  W -- "F6 SQL" --> DB
  W -- "F7 URL da visitare" --> F
  F -- "F8 GET" --> S
  W -- "F9 lookup" --> API
  W -- "F10 aggiornamento" --> BL
  A -- "F11 SSH + CLI" --> B
```

| ID | Da → A | Cosa trasporta | Attraversa un confine? | Protezione principale |
| --- | --- | --- | --- | --- |
| F1 | Browser → Caddy | Credenziali, cookie di sessione, URL da analizzare | Sì: Internet → app | TLS, validazione dell'input, rate limit |
| F2 | Caddy → Backend | Richieste HTTP già terminate in TLS | No | Header di sicurezza aggiunti dal proxy |
| F3 | Backend ↔ PostgreSQL | Utenti, sessioni, analisi | Sì: app → rete interna | Query parametrizzate, utente DB con privilegi minimi |
| F4 | Backend → Redis | ID dei job, contatori dei rate limit | Sì: app → rete interna | Password su Redis, serializzazione JSON |
| F5 | Redis → Worker | ID dei job | Sì: rete interna → app | Il worker rilegge i dati dal DB, non si fida del contenuto della coda |
| F6 | Worker ↔ PostgreSQL | Feature, verdetti, spiegazioni | Sì: app → rete interna | Come F3 |
| F7 | Worker → Fetcher | URL da visitare | Sì: app → rete egress | Il fetcher rivalida tutto e non si fida del worker |
| F8 | Fetcher → Siti analizzati | Richieste GET, risposte ostili | Sì: verso Internet non fidato | Verifica degli IP, IP pinning, redirect controllati, limiti di tempo e dimensione |
| F9 | Worker → API esterne | URL o hash; report in risposta | Sì: verso Internet non fidato | TLS con verifica del certificato, chiavi solo lato server, risposte validate |
| F10 | Worker → Blocklist | Download periodico delle liste | Sì: verso Internet non fidato | TLS, controllo del formato prima dell'uso |
| F11 | Amministratore → Server | Comandi della CLI | Sì: Internet → server | SSH con chiave, audit log (ADR-001) |

## 6. Ipotesi di sicurezza

- **I1.** Il provider di hosting e la sua infrastruttura di virtualizzazione sono affidabili.
- **I2.** Sistema operativo, Docker e immagini base vengono aggiornati regolarmente dall'amministratore.
- **I3.** Il sistema delle Certificate Authority e i certificati TLS emessi tramite Let's Encrypt sono affidabili.
- **I4.** Le API esterne possono essere lente, non disponibili o restituire dati errati: l'app deve funzionare anche senza di esse.
- **I5.** Il dispositivo dell'utente non è compromesso: malware sul computer dell'utente è fuori perimetro.
- **I6.** L'attaccante non ha accesso fisico al server né credenziali SSH valide.
- **I7.** Il progetto non è commerciale e non tratta dati di pagamento; l'unico quadro normativo considerato è il GDPR.

## 7. Analisi STRIDE
| ID | Categoria | Elemento | Minaccia | Mitigazione | Abuse case | ASVS | Test |
| --- | --- | --- | --- | --- | --- | --- | --- |
| S-01 | Spoofing | F1, Backend | Credential stuffing o furto della sessione per prendere il controllo di un account | Argon2id, rate limit sul login, MFA, cookie HttpOnly/Secure/SameSite | AC10 | V6, V7 | `test_login_rate_limit`, `test_session_cookie_flags` |
| T-01 | Tampering | F1 | CSRF: un sito esterno fa compiere azioni all'utente a sua insaputa | Token CSRF, cookie SameSite | — | V3 | `test_csrf_required` |
| R-01 | Repudiation | Backend | Un utente nega di aver cancellato dati o modificato l'account | Audit log delle azioni sensibili | — | V16 | `test_audit_log_events` |
| I-01 | Information disclosure | F1 | Intercettazione del traffico tra browser e server | TLS 1.2 o superiore, HSTS | — | V12 | Verifica con SSL Labs |
| I-02 | Information disclosure | Backend | IDOR: lettura delle analisi di altri utenti cambiando l'ID | Controllo di proprietà centralizzato | AC11 | V8 | `test_idor` |
| D-01 | Denial of service | F1, Backend | Invio massivo di analisi, esaurimento del servizio e delle quote | Rate limit per IP e per utente, quote giornaliere | AC1, AC2 | V2 | `test_quota_exceeded` |
| E-01 | Elevation of privilege | Backend | SQL injection attraverso i campi di input | Query parametrizzate tramite ORM, validazione strict | AC3 | V1 | `test_sql_injection_payloads` |
| E-02 | Elevation of privilege | F7, F8, Fetcher | SSRF: far visitare al fetcher la rete interna o l'endpoint metadata del cloud | Verifica degli IP, IP pinning, redirect rivalidati, isolamento di rete | AC7 | V1, V13 | `test_ssrf` |
| T-02 | Tampering | F8 | La pagina analizzata restituisce contenuti con script che finiscono nell'interfaccia (XSS) | Contenuti mai resi come HTML, escaping, URL defanged | AC3 | V1, V3 | `test_xss_payloads` |
| D-02 | Denial of service | F8 | Il sito risponde lentissimo o con una risposta infinita, bloccando i worker | Timeout totale, dimensione massima della risposta | AC3 | V15 | `test_fetch_limits` |
| R-02 | Repudiation | F8 | Un attaccante usa PhishLens come proxy: le richieste ai siti terzi risultano fatte dal mio server | Solo GET senza header scelti dall'utente, limite per dominio di destinazione, log di ogni richiesta | AC8 | V2 | `test_per_domain_limit` |
| I-03 | Information disclosure | F3, PostgreSQL | Furto delle credenziali del DB: lettura di email, segreti MFA, token di sessione, storico | Credenziali solo come segreti, utente DB con privilegi minimi, segreti TOTP cifrati con chiave esterna al DB, token di sessione salvati come hash | — | V11, V13, V14 | `test_session_tokens_hashed`, `test_totp_secret_encrypted` |
| T-03 | Tampering | PostgreSQL | Con le credenziali del DB, modifica di verdetti, quote o dati degli utenti | Utente DB senza privilegi di modifica dello schema, audit log, backup | — | V13 | Verifica dei permessi dell'utente DB |
| I-04 | Information disclosure | PostgreSQL, Redis | Porta pubblicata per errore nel docker-compose: Docker scavalca ufw e il servizio è esposto su Internet | Nessuna sezione `ports` per db e redis, rete `internal: true`, test in CI sul compose, scansione esterna con nmap | — | V13 | `test_compose_no_exposed_ports`, nmap dopo il deploy |
| I-05 | Information disclosure | Backup | Furto dei backup del database | Backup cifrati, chiave conservata separatamente, copia fuori dal server | — | V14 | Ripristino di prova documentato |
| D-03 | Denial of service | PostgreSQL | Disco pieno o query lente bloccano l'app, anche per abuso volontario | Quote, job di retention, alert sullo spazio disco, `statement_timeout`, pool di connessioni limitato | AC1 | V2 | `test_retention_job`, alert configurato |
| I-06 | Information disclosure | F9, Worker | Chiavi API esposte in un commit, in un log o in un messaggio d'errore | Segreti in variabili d'ambiente, gitleaks, chiavi mascherate nei log, chiavi mai inviate al frontend | AC2 | V13 | gitleaks in CI, `test_logs_no_secrets` |
| T-04 | Tampering | F9 | Le risposte delle API contengono stringhe scelte dall'attaccante che finiscono nell'interfaccia (XSS memorizzata) | Risposte validate con Pydantic, escaping, mai rese come HTML | AC3 | V1 | `test_api_response_xss` |
| T-05 | Tampering | F9 | Man-in-the-middle sulle chiamate alle API: risposte falsificate | TLS con verifica del certificato sempre attiva; regola semgrep contro `verify=False` | — | V12 | Regola semgrep in CI |
| I-07 | Information disclosure | F9 | Gli URL degli utenti, inclusi eventuali token nella query string, diventano visibili a terzi | Ricerca di report esistenti invece dell'invio, visibilità privata, query string rimossa dagli URL inviati all'esterno, informativa | — | V14 | `test_external_url_strips_query` |
| D-04 | Denial of service | F9 | API lenta, non disponibile o con quota esaurita blocca le analisi | Timeout, retry con backoff, circuit breaker, cache, budget giornaliero, risultato parziale | AC2 | V15 | `test_api_timeout_partial_result` |
| S-04 | Spoofing | F2 | Header `X-Forwarded-For` falsificato per cambiare IP apparente e aggirare il rate limit | Il backend accetta l'header solo se arriva da Caddy (proxy fidato) | AC1 | V4 | `test_xff_spoofing_ignored` |
| T-06 | Tampering | F4, F5, Redis | Inserimento di job malevoli nella coda o deserializzazione insicura | Redis con password e solo su rete interna, job in JSON con il solo ID, il worker rilegge i dati dal DB | AC6 | V1 | `test_job_payload_only_id` |
| D-05 | Denial of service | Redis | Coda saturata da job in massa | Limite di job in coda per utente, lunghezza massima della coda | AC1 | V2 | `test_queue_limit_per_user` |
| E-03 | Elevation of privilege | Worker | Un bug nel parsing di contenuti ostili porta all'esecuzione di codice nel worker | Container non root, filesystem in sola lettura, `cap_drop: ALL`, utente DB dedicato con permessi minimi, dipendenze aggiornate, fuzzing | AC3, AC12 | V15 | Trivy, test di fuzzing |
| D-06 | Denial of service | Worker | Email enormi, annidate o con zip bomb esauriscono memoria e CPU | Limiti prima del parsing, allegati solo come hash, timeout per job | AC12 | V5 | `test_eml_limits` |
| S-05 | Spoofing | F7, Fetcher | Un processo diverso dal worker invia richieste al fetcher | Il fetcher accetta richieste solo dalla sua rete dedicata e con un token condiviso | AC7 | V13 | `test_fetcher_rejects_without_token` |
| T-07 | Tampering | F10 | Blocklist manipolata (fonte compromessa o man-in-the-middle) che altera i verdetti | TLS, controllo di formato e dimensione, nuova versione scartata se cambia in modo anomalo | — | V12 | `test_blocklist_validation` |
| T-08 | Tampering | File del modello | Sostituzione del modello con uno manomesso | Formato JSON nativo, hash SHA-256 verificato all'avvio, montaggio in sola lettura | AC6 | V15 | `test_model_hash_mismatch` |
| T-09 | Tampering | Dati di addestramento | Data poisoning tramite feed pubblici | Deduplica, test set fisso verificato a mano, gate di rilascio | AC4 | — | Gate di rilascio in pipeline |
| T-10 | Tampering | Modello | Evasione: URL costruito per abbassare lo score | Test adversarial, segnali esterni indipendenti dal modello | AC5 | — | Report adversarial nella model card |
| I-08 | Information disclosure | Backend | Un phisher usa score e spiegazioni come oracolo per capire come eludere il modello | Rate limit, spiegazioni dettagliate solo agli utenti autenticati, alert su molte varianti dello stesso dominio | AC9 | V2 | `test_variant_alert` |
| S-06 | Spoofing | F11 | Furto della chiave SSH dell'amministratore | Chiave con passphrase, login root disattivato, fail2ban, accesso SSH limitato | — | V13 | Verifica della configurazione SSH |
| R-03 | Repudiation | F11, Audit log | Chi ha accesso al database può alterare l'audit log | Copia dei log su file append-only o servizio esterno | — | V16 | Verifica della copia dei log |

## 8. Abuse case
<!-- La tabella AC1–AC12, collegata alle righe STRIDE. -->

## 9. Rischi residui accettati
- **R1.** Il worker ha accesso a Internet per chiamare le API esterne. Mitigazione prevista: limitare le connessioni in uscita ai soli domini delle API.
- **R2.** I dati di un utente cancellato restano nei backup fino alla loro scadenza (es. 30 giorni). Dichiarato nell'informativa.
- **R3.** Il traffico tra backend e database non è cifrato: resta sulla rete Docker interna dello stesso host.
- **R4.** L'audit log è nel database: chi ottiene accesso al DB può alterarlo. Copia esterna dei log prevista dopo l'MVP.

## 10. Storico delle revisioni
| Versione | Data | Modifica |
| --- | --- | --- |
| 0.1 | AAAA-MM-GG | Prima stesura |