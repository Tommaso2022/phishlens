# ADR-002 — Sessioni lato server invece di JWT

Data: 2026-10-21 · Stato: accettata

## Contesto
L'app deve mantenere l'utente autenticato tra una richiesta e l'altra. Le due opzioni principali sono sessioni salvate sul server con un cookie, oppure token JWT conservati dal client.

## Decisione
Sessioni lato server: un ID casuale in un cookie HttpOnly, Secure, SameSite=Lax; la sessione è salvata nel database come hash.

## Conseguenze
- Positive: logout e revoca immediati; nessun token leggibile da JavaScript in caso di XSS; nessuna gestione di firme e chiavi dei token; il capitolo ASVS V9 non si applica.
- Negative: una lettura sul database a ogni richiesta, trascurabile per questa scala; serve protezione CSRF, prevista comunque.