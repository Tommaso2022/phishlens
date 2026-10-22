"""Esplorazione del dataset preparato: cerca squilibri e possibili scorciatoie.

Uso, dalla radice del repository:
    uv run python -m phishlens_ml.explore

Non stampa URL completi; i nomi di dominio sono mostrati in forma "defanged"
(esempio[.]com), così non diventano link cliccabili.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from phishlens_ml.datasets import DATA_DIR

CLASSES = {0: "legittimi", 1: "phishing"}


def defang(host: str) -> str:
    return host.replace(".", "[.]")


def parts(url: str) -> dict:
    s = url if "://" in url else "http://" + url
    try:
        p = urlsplit(s)
        host = (p.hostname or "").lower()
    except ValueError:
        return {"scheme": "", "host": "", "has_path": False, "has_query": False, "tld": ""}
    return {
        "scheme": p.scheme.lower() if "://" in url else "(assente)",
        "host": host,
        "has_path": p.path not in ("", "/"),
        "has_query": bool(p.query),
        "tld": host.rsplit(".", 1)[-1] if "." in host else "(nessuno)",
    }


def percent(series: pd.Series) -> str:
    return f"{100 * series.mean():5.1f}%"


def report(df: pd.DataFrame) -> None:
    info = pd.DataFrame([parts(u) for u in df["url"]])
    df = pd.concat([df.reset_index(drop=True), info], axis=1)
    df["length"] = df["url"].str.len()

    print(f"URL totali: {len(df)}")
    for k, name in CLASSES.items():
        sub = df[df["is_phishing"] == k]
        print(f"\n== {name}: {len(sub)} ({100 * len(sub) / len(df):.1f}%)")
        print(f"  con un percorso oltre '/':   {percent(sub['has_path'])}")
        print(f"  con parametri (?...):        {percent(sub['has_query'])}")
        print(f"  schema https:                {percent(sub['scheme'] == 'https')}")
        print(f"  senza schema:                {percent(sub['scheme'] == '(assente)')}")
        print(f"  lunghezza mediana:           {sub['length'].median():.0f} caratteri")
        print(f"  host distinti:               {sub['host'].nunique()}")
        top_tld = sub["tld"].value_counts(normalize=True).head(5)
        print(
            "  TLD più frequenti:           "
            + ", ".join(f".{t} {100 * v:.0f}%" for t, v in top_tld.items())
        )
        top_hosts = sub["host"].value_counts().head(5)
        print(
            "  host più ripetuti:           "
            + ", ".join(f"{defang(h)} ({n})" for h, n in top_hosts.items())
        )

    shared = set(df.loc[df["is_phishing"] == 0, "host"]) & set(
        df.loc[df["is_phishing"] == 1, "host"]
    )
    print(f"\nHost presenti in entrambe le classi: {len(shared)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, default=DATA_DIR / "processed" / "phiusiil.parquet")
    args = parser.parse_args(argv)
    report(pd.read_parquet(args.input))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
