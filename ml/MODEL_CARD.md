# Model card — PhishLens, modello del dominio v1.1

Ultimo aggiornamento: 2026-10-23. Hash dei file e composizione dei dati: `ml/model-registry.json`.

## In sintesi
Classificatore XGBoost che stima la probabilità che un **nome di dominio** sia usato
per il phishing, guardando solo il nome: non visita il sito e non usa schema,
percorso o parametri dell'URL. Alla soglia severa riconosce **il 17,2% del phishing
con lo 0,08% di falsi positivi**. È un segnale tra gli altri e non decide da solo
il verdetto (docs/adr/004-il-modello-non-decide-da-solo.md).

## Uso previsto
- Un segnale, con spiegazione, nel verdetto di PhishLens per URL inviati da utenti.
- Non adatto a bloccare automaticamente siti, né a giudicare pagine ospitate su
  piattaforme condivise (web.app, github.io, IPFS, Google Docs): per queste il
  nome di dominio non dice nulla e il modello non viene usato.

## Dati
| Fonte | Uso | Licenza |
| --- | --- | --- |
| PhiUSIIL Phishing URL Dataset (Prasad e Chandra, 2024) | URL legittimi e di phishing; usata solo la colonna con l'URL | CC BY 4.0 |
| Tranco, lista con sottodomini (Le Pochat et al., 2019) | Fino a 30.000 host legittimi con sottodominio | vedi tranco-list.eu |
| Tranco, lista dei domini | Solo valutazione esterna dei falsi positivi | vedi tranco-list.eu |

Preparazione: dagli URL si tiene l'host senza "www."; si tolgono gli host su
piattaforme condivise (in entrambe le classi) e il phishing ospitato su domini che
compaiono tra i legittimi; un solo esempio per host; ogni dominio registrato finisce
in un solo insieme tra training (70%), validazione (15%) e test (15%).
Hash di ogni archivio scaricato: `ml/data-manifest.json`.

## Feature
16 feature calcolate da `phishlens_core.features` (lo stesso codice usato in
produzione): struttura del nome, caratteri calcolati sulla forma Unicode, indirizzo
IP, punycode, marchi noti e parole chiave in inglese e italiano, suffisso pubblico.

## Risultati (test set, mai usato per addestrare né per scegliere le soglie)
| Falsi positivi ammessi (validazione) | Phishing riconosciuto | Falsi positivi reali | Falsi positivi sui legittimi con sottodominio |
| --- | --- | --- | --- |
| 0,1% | 17,2% | 0,08% | 0,22% |
| 1% | 27,3% | 0,86% | 2,62% |

ROC-AUC 0,785, PR-AUC 0,643. Logistic Regression, come riferimento: 13,7% al livello 0,1%.

**Verifica esterna** sui primi 100.000 domini Tranco non presenti nei dati (78.289):
segnalato l'1,43% alla soglia severa. È un limite superiore, perché la classifica
misura la popolarità e include siti di scommesse, spam e TLD abusati. Domini .it
segnalati: 0 su 617.

## Le scorciatoie del dataset
Le metriche si sono abbassate a ogni correzione, ed è il risultato atteso:

| Modello | Cosa vede | Phishing riconosciuto con lo 0,1% di falsi positivi |
| --- | --- | --- |
| Esperimento "ingenuo" | Solo schema, "www.", percorso, parametri e lunghezza dell'URL | 98,9% |
| v1 | Nome di dominio | 55,0% |
| v1.1 | Nome di dominio, senza le scorciatoie trovate | 17,2% |

In PhiUSIIL tutti gli URL legittimi sono homepage in https che iniziano con "www.":
un modello che non sa nulla dei siti raggiunge il 98,9% imparando come sono scritti
gli URL. Nel v1 l'analisi SHAP ha mostrato altre due scorciatoie: i suffissi delle
piattaforme di hosting (web.app, firebaseapp.com) erano 100% phishing, e quasi solo il
phishing aveva sottodomini. Il v1.1 le corregge togliendo le piattaforme condivise e
aggiungendo sottodomini legittimi da Tranco.

## Limiti noti
- Nomi brevi e ordinari (esempio: un ".com" di poche lettere) non sono distinguibili
  da siti legittimi guardando solo il nome.
- Il suffisso è la feature più influente: siti legittimi su TLD economici con cifre
  nel nome ricevono punteggi alti.
- Marchi e parole chiave in contesti leciti (infrastrutture dei marchi stessi)
  producono falsi positivi.
- I legittimi di PhiUSIIL sono siti già noti: il tasso di falsi positivi misurato
  sul test set è ottimistico, quello su Tranco pessimistico.
- I dati risalgono al 2024: il phishing cambia e il modello va rivalutato su dati
  recenti (raccolta da OpenPhish, modello v2).

## Sicurezza
- Il modello è salvato nel formato JSON di XGBoost, mai con pickle, e caricato solo
  se l'hash coincide con quello del registro (`phishlens_core.integrity`).
- Ogni dataset ha l'hash registrato e verificato a ogni esecuzione.
- Previsto con il riaddestramento periodico: test set fisso verificato a mano e
  blocco del rilascio di un modello che peggiora (difesa dal data poisoning).

## Come riprodurre
```bash
uv run python -m phishlens_ml.datasets
uv run python -m phishlens_ml.build
uv run python -m phishlens_ml.train
uv run python -m phishlens_ml.analyze tranco
uv run python -m phishlens_ml.release v1.1
```
