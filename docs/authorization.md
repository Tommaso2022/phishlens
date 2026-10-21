# Regole di autorizzazione — PhishLens

Riferimenti: ASVS v5.0.0-8.1.1, 8.1.2 · Threat model: I-02, AC11

## Principi
1. **Deny by default:** ogni endpoint richiede un utente autenticato, tranne quelli elencati come pubblici.
2. **Proprietà:** un utente accede solo agli oggetti con `owner_id` uguale al proprio ID.
3. **Risposta 404, non 403,** per oggetti di altri utenti: non si rivela che l'oggetto esiste.
4. Le regole sono applicate solo nel backend; il frontend non decide nulla.
5. Nessun ruolo amministratore nell'app (ADR-001).

## Livello di funzione: chi può chiamare cosa

| Endpoint | Anonimo | Utente autenticato |
| --- | --- | --- |
| `GET /health` | Sì | Sì |
| `POST /auth/register`, `/auth/login`, `/auth/verify-email` | Sì | Sì |
| `POST /auth/password-reset/request`, `/confirm` | Sì | Sì |
| `POST /auth/logout` | No | Sì |
| `GET /me`, `PATCH /me` | No | Sì, solo il proprio account |
| `POST /me/mfa/enable`, `/me/mfa/disable` | No | Sì, con password e TOTP |
| `GET /me/export` | No | Sì, con conferma della password |
| `DELETE /me` | No | Sì, con password e TOTP |
| `GET /me/sessions` | No | Sì, solo le proprie |
| `DELETE /me/sessions/{id}` | No | Sì, solo le proprie, con conferma della password |
| `POST /analyses` | No | Sì, entro la quota |
| `GET /analyses` | No | Sì, solo le proprie |
| `GET /analyses/{id}`, `DELETE /analyses/{id}` | No | Sì, solo se proprietario |
| `GET /analyses/{id}/compare` | No | Sì, solo tra analisi proprie |

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
