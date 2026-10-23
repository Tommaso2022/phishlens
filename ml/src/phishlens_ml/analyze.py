"""Analisi del modello: suffissi, errori e falsi positivi su domini esterni.

Uso, dalla radice del repository (dopo phishlens_ml.train):
    uv run python -m phishlens_ml.analyze suffix
    uv run python -m phishlens_ml.analyze errors
    uv run python -m phishlens_ml.analyze tranco

I domini sono stampati in forma "defanged" (esempio[.]com): non diventano link.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from phishlens_core.explain import top_reasons
from phishlens_core.features import FEATURE_NAMES, extract_host_features, registered_domain
from phishlens_core.url import InvalidURL, parse_url

from phishlens_ml import datasets as ds
from phishlens_ml import tranco
from phishlens_ml.train import ARTIFACTS, matrix

HOSTS = ds.DATA_DIR / "processed" / "hosts.parquet"


def defang(host: str) -> str:
    return host.replace(".", "[.]")


class Model:
    """Modello v1 con il suo vocabolario dei suffissi e le soglie scelte in validazione."""

    def __init__(self, artifacts: Path = ARTIFACTS, version: str = "v1.1"):
        self.booster = xgb.Booster()
        self.booster.load_model(artifacts / f"model-{version}.json")
        self.vocab = json.loads((artifacts / f"suffix-vocab-{version}.json").read_text())
        report = json.loads((artifacts / f"report-{version}.json").read_text())
        self.thresholds = {
            p["target_fpr"]: p["threshold"] for p in report["xgboost"]["operating_points"]
        }

    def score(self, df: pd.DataFrame) -> tuple[np.ndarray, pd.DataFrame]:
        """Probabilità di phishing e contributi SHAP per ogni feature."""
        dm = xgb.DMatrix(matrix(df, self.vocab), enable_categorical=True)
        scores = self.booster.predict(dm)
        contrib = self.booster.predict(dm, pred_contribs=True)[:, :-1]
        return scores, pd.DataFrame(contrib, columns=list(FEATURE_NAMES), index=df.index)


def reasons_line(row: pd.Series, contrib: pd.Series, direction: str = "risk") -> str:
    feats = {f: row[f] for f in FEATURE_NAMES}
    rs = top_reasons(feats, contrib.to_dict(), k=3, direction=direction)
    return "; ".join(r.text for r in rs) or "(nessuna ragione prevalente)"


# ------------------------------------------------------------------ suffix


def cmd_suffix(model: Model, hosts: pd.DataFrame, top: int = 15) -> None:
    train = hosts[hosts["split"] == "train"]
    test = hosts[hosts["split"] == "test"]
    _, contrib = model.score(test)
    counts = train.groupby(["suffix", "is_phishing"]).size().unstack(fill_value=0)
    counts.columns = ["legittimi", "phishing"]
    chosen = list(counts.sum(axis=1).sort_values(ascending=False).head(top).index)
    for extra in ("it", "eu"):
        if extra in counts.index and extra not in chosen:
            chosen.append(extra)

    print("Suffisso       legittimi  phishing  % phishing  effetto medio sul punteggio (test)")
    for s in chosen:
        legit, phish = counts.loc[s, "legittimi"], counts.loc[s, "phishing"]
        effect = contrib.loc[test["suffix"] == s, "suffix"].mean()
        effect_txt = "      n/d" if np.isnan(effect) else f"{effect:+9.3f}"
        print(f".{s:<12} {legit:10} {phish:9} {100 * phish / (legit + phish):10.1f}%  {effect_txt}")
    print("\nEffetto > 0: il suffisso spinge verso il phishing; < 0 verso il legittimo.")


# ------------------------------------------------------------------ errors


def cmd_errors(model: Model, hosts: pd.DataFrame, n_missed: int = 10) -> None:
    test = hosts[hosts["split"] == "test"]
    scores, contrib = model.score(test)
    target = min(model.thresholds)
    thr = model.thresholds[target]

    fp = test[(scores > thr) & (test["is_phishing"] == 0)]
    print(f"Falsi positivi alla soglia severa ({target:.1%} ammessi): {len(fp)}\n")
    for idx in fp.index[np.argsort(-scores[test.index.get_indexer(fp.index)])]:
        s = scores[test.index.get_loc(idx)]
        why = reasons_line(fp.loc[idx], contrib.loc[idx])
        print(f"  {defang(fp.at[idx, 'host']):40} {s:.3f}  {why}")

    fn = test[(scores <= thr) & (test["is_phishing"] == 1)]
    sample = fn.sample(min(n_missed, len(fn)), random_state=1)
    print(
        f"\nPhishing non riconosciuto: {len(fn)} su {int(test['is_phishing'].sum())}. Campione:\n"
    )
    for idx in sample.index:
        s = scores[test.index.get_loc(idx)]
        why = reasons_line(sample.loc[idx], contrib.loc[idx], direction="safe")
        print(f"  {defang(sample.at[idx, 'host']):40} {s:.3f}  sembra legittimo perché: {why}")


# ------------------------------------------------------------------ tranco


def cmd_tranco(
    model: Model, hosts: pd.DataFrame, data_dir: Path, manifest_path: Path, top_n: int
) -> None:
    manifest = ds.load_manifest(manifest_path)
    raw = tranco.fetch("domains", data_dir, manifest)
    ds.save_manifest(manifest, manifest_path)

    known = set(hosts["registered_domain"])
    rows, skipped_known, invalid = [], 0, 0
    for d in tranco.read(raw, top_n):
        try:
            host = parse_url(f"https://{d}/").site_host
        except InvalidURL:
            invalid += 1
            continue
        if registered_domain(host) in known:
            skipped_known += 1
            continue
        rows.append({"host": host, **extract_host_features(host)})
    df = pd.DataFrame(rows).drop_duplicates("host").reset_index(drop=True)
    print(
        f"Tranco primi {top_n}: {len(df)} domini nuovi analizzati "
        f"({skipped_known} già in PhiUSIIL, {invalid} non validi)."
    )

    scores, contrib = model.score(df)
    for target, thr in sorted(model.thresholds.items()):
        flagged = scores > thr
        it = df["suffix"] == "it"
        print(f"\nSoglia per {target:.1%} di falsi positivi in validazione:")
        print(f"  segnalati: {int(flagged.sum())} su {len(df)} ({flagged.mean():.2%})")
        if it.any():
            print(
                f"  di cui .it: {int((flagged & it).sum())} su {int(it.sum())} "
                f"({(flagged[it]).mean():.2%})"
            )

    thr = model.thresholds[min(model.thresholds)]
    worst = np.argsort(-scores)[:15]
    print(
        "\nI 15 domini con il punteggio più alto (da verificare a mano: Tranco può "
        "contenere anche domini abusati):"
    )
    for i in worst:
        mark = "segnalato" if scores[i] > thr else "         "
        print(
            f"  {mark} {defang(df.at[i, 'host']):38} {scores[i]:.3f}  "
            f"{reasons_line(df.loc[i], contrib.loc[i])}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["suffix", "errors", "tranco"])
    parser.add_argument("--hosts", type=Path, default=HOSTS)
    parser.add_argument("--artifacts", type=Path, default=ARTIFACTS)
    parser.add_argument("--data-dir", type=Path, default=ds.DATA_DIR)
    parser.add_argument("--manifest", type=Path, default=ds.MANIFEST)
    parser.add_argument("--top", type=int, default=100_000, help="domini Tranco da analizzare")
    parser.add_argument("--version", default="v1.1", help="versione del modello da analizzare")
    args = parser.parse_args(argv)

    model = Model(args.artifacts, args.version)
    hosts = pd.read_parquet(args.hosts)
    try:
        if args.command == "suffix":
            cmd_suffix(model, hosts)
        elif args.command == "errors":
            cmd_errors(model, hosts)
        else:
            cmd_tranco(model, hosts, args.data_dir, args.manifest, args.top)
    except ds.DatasetError as e:
        print(f"ERRORE: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
