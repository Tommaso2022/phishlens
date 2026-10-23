"""Costruzione del dataset dei domini per il modello v1.

Uso, dalla radice del repository:
    uv run python -m phishlens_ml.build

Da ogni URL tiene solo l'host senza "www." (vedi phishlens_core.features),
toglie il phishing ospitato su piattaforme legittime, elimina i duplicati,
calcola le feature e assegna ogni dominio registrato a uno solo dei tre
insiemi: training, validazione, test.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from phishlens_core.features import extract_host_features, registered_domain
from phishlens_core.url import InvalidURL, parse_url

from phishlens_ml.datasets import DATA_DIR

# Servizi legittimi usati per ospitare pagine di phishing. Per questi il
# dominio non dice nulla: il modello v1, basato solo sul dominio, non può
# riconoscerli, e vanno gestiti con blocklist e servizi esterni.
SHARED_HOSTING = frozenset(
    {
        "ipfs.io",
        "cloudflare-ipfs.com",
        "dweb.link",
        "w3s.link",
        "nftstorage.link",
        "fleek.co",
        "4everland.io",
    }
)

SPLITS = {"train": 0.70, "validation": 0.15, "test": 0.15}
SEED = 20261022


def to_hosts(df: pd.DataFrame) -> tuple[pd.DataFrame, Counter]:
    """Converte gli URL in host normalizzati; conta gli URL scartati per motivo."""
    rows, dropped = [], Counter()
    for url, label in zip(df["url"], df["is_phishing"], strict=True):
        try:
            host = parse_url(url).site_host
        except InvalidURL as e:
            dropped[f"URL non valido ({str(e).split(':')[0]})"] += 1
            continue
        rows.append((host, registered_domain(host), int(label)))
    return pd.DataFrame(rows, columns=["host", "registered_domain", "is_phishing"]), dropped


def remove_platform_hosted(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Toglie il phishing ospitato su domini legittimi o su piattaforme condivise."""
    legit_domains = set(df.loc[df["is_phishing"] == 0, "registered_domain"])
    phishing = df["is_phishing"] == 1
    hosted = phishing & (
        df["registered_domain"].isin(legit_domains) | df["registered_domain"].isin(SHARED_HOSTING)
    )
    return df[~hosted], int(hosted.sum())


def deduplicate(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Un solo esempio per host; gli host con etichette in conflitto vengono tolti."""
    n_labels = df.groupby("host")["is_phishing"].transform("nunique")
    conflicts = int(df.loc[n_labels > 1, "host"].nunique())
    df = df[n_labels == 1].drop_duplicates("host")
    return df.reset_index(drop=True), conflicts


def assign_splits(df: pd.DataFrame, seed: int = SEED) -> pd.Series:
    """Assegna ogni dominio registrato a un solo insieme (niente leakage tra insiemi)."""
    domains = df["registered_domain"].drop_duplicates().to_numpy()
    rng = np.random.default_rng(seed)
    rng.shuffle(domains)
    cuts = np.cumsum([int(len(domains) * f) for f in list(SPLITS.values())[:-1]])
    names = np.empty(len(domains), dtype=object)
    for name, part in zip(SPLITS, np.split(np.arange(len(domains)), cuts), strict=True):
        names[part] = name
    return df["registered_domain"].map(dict(zip(domains, names, strict=True)))


def build(urls: pd.DataFrame) -> pd.DataFrame:
    hosts, dropped = to_hosts(urls)
    hosts, platform = remove_platform_hosted(hosts)
    hosts, conflicts = deduplicate(hosts)
    features = pd.DataFrame([extract_host_features(h) for h in hosts["host"]])
    out = pd.concat([hosts, features], axis=1)
    out["split"] = assign_splits(out)

    print(f"URL in ingresso: {len(urls)}")
    for reason, n in dropped.most_common():
        print(f"  scartati, {reason}: {n}")
    print(f"  phishing su piattaforme o domini legittimi, tolto: {platform}")
    print(f"  host con etichette in conflitto, tolti: {conflicts}")
    print(f"Host unici nel dataset: {len(out)}")
    summary = out.groupby(["split", "is_phishing"]).size().unstack(fill_value=0)
    summary.columns = ["legittimi", "phishing"]
    print(summary.loc[list(SPLITS)].to_string())
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, default=DATA_DIR / "processed" / "phiusiil.parquet")
    parser.add_argument("--output", type=Path, default=DATA_DIR / "processed" / "hosts.parquet")
    args = parser.parse_args(argv)
    out = build(pd.read_parquet(args.input))
    out.to_parquet(args.output, index=False)
    print(f"Salvato {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
