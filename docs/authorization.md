# Regole di autorizzazione — PhishLens

Riferimenti: ASVS v5.0.0-8.1.1, 8.1.2 · Threat model: I-02, AC11

## Principi
1. **Deny by default:** ogni endpoint richiede un utente autenticato, tranne quelli elencati come pubblici.
2. **Proprietà:** un utente accede solo agli oggetti con `owner_id` uguale al proprio ID.
3. **Risposta 404, non 403,** per oggetti di altri utenti: non si rivela che l'oggetto esiste.
4. Le regole sono applicate solo nel backend; il frontend non decide nulla.
5. Nessun ruolo amministratore nell'app (ADR-001).

## Livello di funzione: chi può chiamare cosa

Il livello d'accesso di ogni route è dichiarato in un solo punto, `backend/src/phishlens_backend/authz.py` (`ROUTE_POLICY`). I test di `backend/tests/test_authorization.py` falliscono se una route non ha un livello dichiarato, se la protezione nel codice è diversa da quella dichiarata, se una route protetta risponde senza la sessione giusta o se una route non compare in questa tabella. "Utente autenticato" significa sessione completa (password e secondo fattore), salvo dove indicato.

| Endpoint | Anonimo | Utente autenticato |
| --- | --- | --- |
| `GET /health` | Sì | Sì |
| `POST /auth/register`, `/auth/login`, `/auth/verify-email` | Sì | Sì |
| `POST /auth/password-reset/request`, `/confirm` | Sì | Sì |
| `POST /auth/totp/setup`, `/auth/totp/confirm` | No | Solo con sessione parziale, alla prima configurazione del TOTP |
| `POST /auth/login/totp`, `/auth/login/recovery` | No | Solo con sessione parziale (password già verificata) |
| `POST /auth/logout` | No | Sì, con sessione parziale o completa |
| `GET /me`, `PATCH /me` | No | Sì, solo il proprio account |
| `POST /me/mfa/enable`, `/me/mfa/disable` | No | Sì, con password e TOTP |
| `GET /me/export` | No | Sì, con conferma della password |
| `DELETE /me` | No | Sì, con password e TOTP |
| `GET /me/sessions` | No | Sì, solo le proprie |
| `POST /me/sessions/{id}/revoke` | No | Sì, solo le proprie, con conferma della password |
| `POST /me/sessions/revoke-others` | No | Sì, con conferma della password |
| `POST /me/password` | No | Sì, con password attuale e TOTP |
| `POST /me/recovery-codes` | No | Sì, con password e TOTP |
| `POST /analyses` | No | Sì, entro la quota |

## Livello di campo: chi può leggere e scrivere ogni campo

| Oggetto.campo | Lettura | Scrittura |
| --- | --- | --- |
| User.email | Proprietario | Proprietario, con nuova verifica email |
| User.password_hash | Mai esposto | Solo tramite cambio o reset password |
| User.totp_secret | Mai esposto dopo l'attivazione | Solo tramite il flusso MFA |
| User.daily_quota, is_active, is_verified | Proprietario (solo lettura) | Solo sistema o CLI admin |
| Analysis.id, owner_id, created_at | Proprietario | Solo sistema; `owner_id` preso dalla sessione, mai dall'input |
| Analysis.url | Proprietario | Solo alla creazione |
| Analysis.score, verdict, explanation | Proprietario | Solo il worker |
