"""Costruzione del dataset dei domini per il modello v1.1.

Uso, dalla radice del repository:
    uv run python -m phishlens_ml.build

Da ogni URL tiene solo l'host senza "www." (vedi phishlens_core.features),
toglie gli host su piattaforme condivise e il phishing ospitato su domini
legittimi, aggiunge host legittimi con sottodomini presi da Tranco, elimina
i duplicati, calcola le feature e assegna ogni dominio registrato a uno solo
dei tre insiemi: training, validazione, test.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from phishlens_core.features import (
    extract_host_features,
    is_shared_platform,
    registered_domain,
    split_host,
)
from phishlens_core.url import InvalidURL, parse_url

from phishlens_ml import datasets as ds
from phishlens_ml import tranco

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
        rows.append((host, registered_domain(host), int(label), "phiusiil"))
    cols = ["host", "registered_domain", "is_phishing", "source"]
    return pd.DataFrame(rows, columns=cols), dropped


def remove_platforms(df: pd.DataFrame) -> tuple[pd.DataFrame, int, int]:
    """Toglie gli host su piattaforme condivise (entrambe le classi) e il
    phishing ospitato su domini che compaiono anche tra i legittimi."""
    shared = df["host"].map(is_shared_platform)
    df = df[~shared]
    legit_domains = set(df.loc[df["is_phishing"] == 0, "registered_domain"])
    hosted = (df["is_phishing"] == 1) & df["registered_domain"].isin(legit_domains)
    return df[~hosted], int(shared.sum()), int(hosted.sum())


def tranco_subdomain_hosts(
    names: list[str], phishing_domains: set[str], max_n: int, seed: int = SEED
) -> pd.DataFrame:
    """Host legittimi con sottodomini (it.wikipedia.org, ...) presi da Tranco.

    Esclusi: host non validi, piattaforme condivise, domini registrati che
    compaiono tra il phishing (per non creare etichette in conflitto).
    """
    rows = []
    for name in names:
        try:
            host = parse_url(f"https://{name}/").site_host
        except InvalidURL:
            continue
        if not split_host(host)[0] or is_shared_platform(host):
            continue
        reg = registered_domain(host)
        if reg in phishing_domains:
            continue
        rows.append((host, reg, 0, "tranco"))
    df = pd.DataFrame(rows, columns=["host", "registered_domain", "is_phishing", "source"])
    df = df.drop_duplicates("host")
    if len(df) > max_n:
        df = df.sample(max_n, random_state=seed)
    return df.reset_index(drop=True)


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


def build(
    urls: pd.DataFrame, tranco_names: list[str] | None = None, tranco_max: int = 30_000
) -> pd.DataFrame:
    hosts, dropped = to_hosts(urls)
    hosts, shared, hosted = remove_platforms(hosts)
    added = 0
    if tranco_names:
        phishing_domains = set(hosts.loc[hosts["is_phishing"] == 1, "registered_domain"])
        extra = tranco_subdomain_hosts(tranco_names, phishing_domains, tranco_max)
        added = len(extra)
        hosts = pd.concat([hosts, extra], ignore_index=True)
    hosts, conflicts = deduplicate(hosts)
    features = pd.DataFrame([extract_host_features(h) for h in hosts["host"]])
    out = pd.concat([hosts, features], axis=1)
    out["split"] = assign_splits(out)

    print(f"URL in ingresso: {len(urls)}")
    for reason, n in dropped.most_common():
        print(f"  scartati, {reason}: {n}")
    print(f"  host su piattaforme condivise, tolti: {shared}")
    print(f"  phishing su domini presenti tra i legittimi, tolto: {hosted}")
    print(f"  host legittimi con sottodominio aggiunti da Tranco: {added}")
    print(f"  host con etichette in conflitto, tolti: {conflicts}")
    print(f"Host unici nel dataset: {len(out)}")
    summary = out.groupby(["split", "is_phishing"]).size().unstack(fill_value=0)
    summary.columns = ["legittimi", "phishing"]
    print(summary.loc[list(SPLITS)].to_string())
    with_sub = out[(out["is_phishing"] == 0) & (out["n_subdomain_labels"] > 0)]
    print(
        f"Legittimi con sottodominio: {len(with_sub)} "
        f"({(with_sub['source'] == 'tranco').mean():.0%} da Tranco)"
    )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--input", type=Path, default=ds.DATA_DIR / "processed" / "phiusiil.parquet"
    )
    parser.add_argument("--output", type=Path, default=ds.DATA_DIR / "processed" / "hosts.parquet")
    parser.add_argument("--data-dir", type=Path, default=ds.DATA_DIR)
    parser.add_argument("--manifest", type=Path, default=ds.MANIFEST)
    parser.add_argument(
        "--tranco-top",
        type=int,
        default=200_000,
        help="posizioni della lista Tranco con sottodomini da considerare",
    )
    parser.add_argument(
        "--tranco-max",
        type=int,
        default=30_000,
        help="massimo di host legittimi da aggiungere (0 = nessuno)",
    )
    args = parser.parse_args(argv)

    names = None
    try:
        if args.tranco_max > 0:
            manifest = ds.load_manifest(args.manifest)
            raw = tranco.fetch("subdomains", args.data_dir, manifest)
            ds.save_manifest(manifest, args.manifest)
            names = tranco.read(raw, args.tranco_top)
    except ds.DatasetError as e:
        print(f"ERRORE: {e}")
        return 1
    out = build(pd.read_parquet(args.input), names, args.tranco_max)
    out.to_parquet(args.output, index=False)
    print(f"Salvato {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
