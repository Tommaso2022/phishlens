"""Dati sintetici per i test: domini inventati, nessun URL reale.

I casi limite inclusi servono a verificare i filtri di phishlens_ml.build.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

WORDS = ["sole", "mare", "libro", "casa", "verde", "tecno", "studio", "arte", "viaggi", "cucina"]


def synthetic_urls(n: int = 1500, seed: int = 1) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        w = str(rng.choice(WORDS)) + str(rng.choice(WORDS)) + str(i)
        rows.append((f"https://www.{w}.{rng.choice(['com', 'it', 'org'])}", 0))
        brand = rng.choice(["paypal", "poste", "amazon"])
        tld = rng.choice(["xyz", "top", "com"])
        rows.append((f"http://{brand}.{w}-verifica-{rng.integers(100, 999)}.{tld}/login?id={i}", 1))
    rows.append(("https://www.esempio-legittimo.com", 0))
    rows.append(("http://docs.esempio-legittimo.com/phish", 1))  # dominio presente tra i legittimi
    rows.append(("https://qualcosa.ipfs.io/x", 1))  # piattaforma condivisa
    rows.append(("https://accesso-banca.web.app/", 1))  # suffisso privato (Firebase)
    rows.append(("https://utente:pw@esempio.test/", 1))  # URL non valido
    return pd.DataFrame(rows, columns=["url", "is_phishing"])
