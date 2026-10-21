# ADR-001 — Nessun pannello di amministrazione web

Data: 2026-10-20 · Stato: accettata

## Contesto
L'app ha bisogno di operazioni di amministrazione: gestione utenti, quote, versioni del modello, cancellazioni su richiesta. Un pannello web esposto su Internet sarebbe un bersaglio di alto valore: account amministratore da rubare, pagina /admin da scoprire, rischio di escalation di privilegi.

## Decisione
L'amministrazione avviene tramite una CLI eseguita sul server dopo accesso SSH con chiave. Gli strumenti di monitoraggio ascoltano solo su localhost e si raggiungono tramite tunnel SSH. Ogni comando amministrativo viene registrato nell'audit log.

## Conseguenze
- Positive: superficie d'attacco ridotta; nessun ruolo amministratore nell'app; i privilegi derivano dall'accesso al server.
- Negative: amministrare richiede competenze da terminale; non adatto a più amministratori non tecnici.
- Se in futuro servisse un pannello, sarà un'applicazione separata, raggiungibile solo via VPN, con MFA obbligatoria.