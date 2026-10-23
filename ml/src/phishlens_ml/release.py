"""Registrazione di una versione del modello in ml/model-registry.json.

Uso, dalla radice del repository (dopo train):
    uv run python -m phishlens_ml.release v1.1

Il registro è nel repository; i file del modello restano in ml/artifacts/
(esclusa da Git). Per ogni versione registra: hash dei file, metriche
principali, composizione dei dati e hash dei dataset usati. Una versione già
registrata non può essere sovrascritta con file diversi.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
from phishlens_core.integrity import sha256_file

from phishlens_ml import datasets as ds
from phishlens_ml.train import ARTIFACTS

REGISTRY = ds.ML_DIR / "model-registry.json"


def summarize_data(hosts: pd.DataFrame) -> dict:
    counts = hosts.groupby(["split", "source", "is_phishing"]).size()
    out: dict = {}
    for (split, source, label), n in counts.items():
        key = "phishing" if label == 1 else "legittimi"
        out.setdefault(split, {}).setdefault(source, {})[key] = int(n)
    return out


def release(
    version: str, artifacts: Path, hosts_path: Path, registry: Path, manifest: Path
) -> dict:
    files = [f"model-{version}.json", f"suffix-vocab-{version}.json"]
    for name in files:
        if not (artifacts / name).exists():
            raise ds.DatasetError(f"Manca {artifacts / name}: esegui prima train.")
    report = json.loads((artifacts / f"report-{version}.json").read_text())
    entry = {
        "created": datetime.now(UTC).strftime("%Y-%m-%d"),
        "files": {name: sha256_file(artifacts / name) for name in files},
        "model_bytes": (artifacts / files[0]).stat().st_size,
        "thresholds": {
            str(p["target_fpr"]): p["threshold"] for p in report["xgboost"]["operating_points"]
        },
        "metrics_test": {
            "roc_auc": report["xgboost"]["roc_auc"],
            "pr_auc": report["xgboost"]["pr_auc"],
            "operating_points": report["xgboost"]["operating_points"],
        },
        "data": summarize_data(pd.read_parquet(hosts_path)),
        "datasets": {k: v["sha256"] for k, v in ds.load_manifest(manifest).items()},
    }
    reg = json.loads(registry.read_text()) if registry.exists() else {}
    old = reg.get(version)
    if old and old["files"] != entry["files"]:
        raise ds.DatasetError(
            f"La versione {version} è già registrata con file diversi: usa un nuovo nome."
        )
    reg[version] = entry
    registry.write_text(json.dumps(reg, indent=2, ensure_ascii=False) + "\n")
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version")
    parser.add_argument("--artifacts", type=Path, default=ARTIFACTS)
    parser.add_argument("--hosts", type=Path, default=ds.DATA_DIR / "processed" / "hosts.parquet")
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--manifest", type=Path, default=ds.MANIFEST)
    args = parser.parse_args(argv)
    try:
        entry = release(args.version, args.artifacts, args.hosts, args.registry, args.manifest)
    except ds.DatasetError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        return 1
    print(f"Registrata la versione {args.version} in {args.registry}")
    for name, h in entry["files"].items():
        print(f"  {name}: {h}")
    print(f"  dimensione del modello: {entry['model_bytes'] / 1024:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
