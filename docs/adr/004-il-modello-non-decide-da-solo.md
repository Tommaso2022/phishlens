# ADR-004 — Il modello ML non decide da solo

Data: 2026-10-23 · Stato: accettata

## Contesto
Il modello v1.1, basato solo sul nome di dominio, riconosce il 17,2% del phishing
con lo 0,08% di falsi positivi sul test set (ml/MODEL_CARD.md). I suoi errori hanno
una causa ricorrente: dà molto peso al suffisso, quindi un sito legittimo su un TLD
economico (.xyz, .top, .info) con cifre nel nome riceve un punteggio alto. La
priorità del progetto è generare pochissimi falsi positivi: un utente che vede
segnalati siti legittimi smette di fidarsi anche degli allarmi veri.

## Decisione
Il punteggio del modello è un segnale tra gli altri, mai sufficiente da solo per
il verdetto più grave.

| Verdetto | Quando |
| --- | --- |
| Alto rischio | Segnalazione da blocklist o servizi esterni, oppure punteggio ML sopra la soglia severa e dominio registrato da meno di 30 giorni |
| Sospetto | Punteggio ML sopra la soglia severa senza conferme, oppure dominio registrato da meno di 30 giorni senza altri segnali |
| Nessun segnale di rischio rilevato | Tutti gli altri casi |

Gli host su piattaforme condivise (web.app, github.io, IPFS, ...) non ricevono un
punteggio ML: il verdetto dipende solo dai segnali esterni, e l'interfaccia spiega
che il nome di dominio non è indicativo. Ogni verdetto mostra le ragioni che lo
hanno determinato.

## Conseguenze
- Positive: un sito legittimo può risultare al massimo "sospetto" per il solo nome,
  e l'utente vede perché; i falsi positivi del modello non diventano allarmi gravi.
- Negative: il phishing riconosciuto solo dal modello resta "sospetto" e non "alto
  rischio"; il verdetto dipende dalla disponibilità dei servizi esterni e dell'età
  del dominio (RDAP), che vanno gestiti con risultati parziali (docs/validation.md).
- La soglia di 30 giorni e la combinazione dei segnali vanno verificate sui dati
  raccolti da OpenPhish (modello v2) e riviste se necessario.
