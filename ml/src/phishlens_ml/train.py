"""Addestramento e valutazione dei modelli v1, con priorità ai pochi falsi positivi.

Uso, dalla radice del repository (dopo phishlens_ml.build):
    uv run python -m phishlens_ml.train

Addestra due modelli sulle feature del dominio:
  - Logistic Regression: modello di riferimento, semplice e interpretabile;
  - XGBoost: modello principale.
Poi esegue l'esperimento "ingenuo": un modello che vede schema, percorso e
parametri dell'URL completo, per mostrare le scorciatoie del dataset.

Le soglie si scelgono sull'insieme di validazione in base al tasso di falsi
positivi ammesso; le metriche finali si calcolano solo sull'insieme di test.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import xgboost as xgb
from phishlens_core.features import NUMERIC_FEATURES, registered_domain
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from phishlens_ml.build import assign_splits
from phishlens_ml.datasets import DATA_DIR

ARTIFACTS = DATA_DIR.parent / "artifacts"
TARGET_FPRS = (0.001, 0.01)  # 1 legittimo su 1000, 1 su 100
TOP_SUFFIXES = 50
OTHER = "(altro)"
SEED = 20261022


# ---------------------------------------------------------------- utilità


def suffix_vocabulary(train: pd.DataFrame, k: int = TOP_SUFFIXES) -> list[str]:
    """I suffissi più frequenti nel training; gli altri diventano "(altro)".

    Il vocabolario si salva insieme al modello: in produzione serve lo stesso.
    """
    return train["suffix"].value_counts().head(k).index.tolist()


def matrix(df: pd.DataFrame, vocab: list[str]) -> pd.DataFrame:
    x = df[list(NUMERIC_FEATURES)].astype(float).copy()
    suffix = df["suffix"].where(df["suffix"].isin(vocab), OTHER)
    x["suffix"] = pd.Categorical(suffix, categories=[*vocab, OTHER])
    return x


def threshold_for_fpr(scores_legit: np.ndarray, fpr: float) -> float:
    """Soglia più bassa che, sui legittimi di validazione, non supera il tasso indicato."""
    return float(np.quantile(scores_legit, 1 - fpr, method="higher"))


def evaluate(y: np.ndarray, scores: np.ndarray, thresholds: dict[float, float]) -> dict:
    result = {
        "roc_auc": round(float(roc_auc_score(y, scores)), 4),
        "pr_auc": round(float(average_precision_score(y, scores)), 4),
        "operating_points": [],
    }
    for target, thr in thresholds.items():
        flagged = scores > thr
        tp = int((flagged & (y == 1)).sum())
        fp = int((flagged & (y == 0)).sum())
        result["operating_points"].append(
            {
                "target_fpr": target,
                "threshold": round(thr, 6),
                "fpr": round(fp / max(int((y == 0).sum()), 1), 5),
                "recall": round(tp / max(int((y == 1).sum()), 1), 4),
                "precision": round(tp / max(tp + fp, 1), 4),
                "false_positives": fp,
            }
        )
    return result


def mean_abs_shap(booster: xgb.Booster, x: pd.DataFrame) -> dict[str, float]:
    """Importanza media |SHAP| con TreeSHAP integrato in XGBoost."""
    contrib = booster.predict(xgb.DMatrix(x, enable_categorical=True), pred_contribs=True)
    values = np.abs(contrib[:, :-1]).mean(axis=0)  # l'ultima colonna è il valore base
    ranking = sorted(zip(x.columns, values, strict=True), key=lambda t: -t[1])
    return {name: round(float(v), 4) for name, v in ranking}


def fit_xgboost(x_tr, y_tr, x_va, y_va) -> xgb.XGBClassifier:
    model = xgb.XGBClassifier(
        n_estimators=600,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        enable_categorical=True,
        eval_metric="aucpr",
        early_stopping_rounds=40,
        random_state=SEED,
        n_jobs=-1,
    )
    model.fit(x_tr, y_tr, eval_set=[(x_va, y_va)], verbose=False)
    return model


def print_result(name: str, res: dict) -> None:
    print(f"\n== {name}")
    print(f"  ROC-AUC {res['roc_auc']}   PR-AUC {res['pr_auc']}")
    for p in res["operating_points"]:
        print(
            f"  falsi positivi ammessi {p['target_fpr']:.1%}: "
            f"phishing riconosciuto {p['recall']:.1%}, "
            f"falsi positivi reali {p['fpr']:.2%} ({p['false_positives']}), "
            f"precisione {p['precision']:.1%}"
        )


# ---------------------------------------------------------------- modelli v1


def train_v1(hosts: pd.DataFrame) -> tuple[dict, xgb.XGBClassifier, list[str]]:
    parts = {s: hosts[hosts["split"] == s] for s in ("train", "validation", "test")}
    vocab = suffix_vocabulary(parts["train"])
    x = {s: matrix(d, vocab) for s, d in parts.items()}
    y = {s: d["is_phishing"].to_numpy() for s, d in parts.items()}
    report: dict = {}

    # Logistic Regression: suffisso in one-hot, numeriche standardizzate.
    lr = make_pipeline(
        ColumnTransformer(
            [
                ("num", StandardScaler(), list(NUMERIC_FEATURES)),
                ("suf", OneHotEncoder(handle_unknown="ignore"), ["suffix"]),
            ]
        ),
        LogisticRegression(max_iter=3000),
    )
    lr.fit(x["train"], y["train"])
    s_va = lr.predict_proba(x["validation"])[:, 1]
    thr = {f: threshold_for_fpr(s_va[y["validation"] == 0], f) for f in TARGET_FPRS}
    report["logistic_regression"] = evaluate(y["test"], lr.predict_proba(x["test"])[:, 1], thr)
    print_result("Logistic Regression (dominio)", report["logistic_regression"])

    model = fit_xgboost(x["train"], y["train"], x["validation"], y["validation"])
    s_va = model.predict_proba(x["validation"])[:, 1]
    thr = {f: threshold_for_fpr(s_va[y["validation"] == 0], f) for f in TARGET_FPRS}
    report["xgboost"] = evaluate(y["test"], model.predict_proba(x["test"])[:, 1], thr)
    report["xgboost"]["best_iteration"] = int(model.best_iteration)
    report["xgboost"]["shap_mean_abs"] = mean_abs_shap(model.get_booster(), x["test"])
    print_result("XGBoost (dominio)", report["xgboost"])
    top = list(report["xgboost"]["shap_mean_abs"].items())[:5]
    print("  feature più influenti (|SHAP| medio): " + ", ".join(f"{k} {v}" for k, v in top))
    return report, model, vocab


# ---------------------------------------------------------- esperimento ingenuo

NAIVE_FEATURES = ("is_https", "starts_www", "has_path", "has_query", "url_length")


def naive_features(urls: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for url in urls["url"]:
        p = urlsplit(url if "://" in url else "http://" + url)
        host = (p.hostname or "").lower()
        rows.append(
            {
                "is_https": int(p.scheme.lower() == "https"),
                "starts_www": int(host.startswith("www.")),
                "has_path": int(p.path not in ("", "/")),
                "has_query": int(bool(p.query)),
                "url_length": len(url),
                "registered_domain": registered_domain(host.removeprefix("www.")) if host else "",
            }
        )
    return pd.DataFrame(rows)


def naive_experiment(urls: pd.DataFrame) -> dict:
    """Un modello che vede solo come è scritto l'URL, non il dominio."""
    f = naive_features(urls)
    f["is_phishing"] = urls["is_phishing"].to_numpy()
    f["split"] = assign_splits(f)
    cols = list(NAIVE_FEATURES)
    d = {s: f[f["split"] == s] for s in ("train", "validation", "test")}
    model = fit_xgboost(
        d["train"][cols],
        d["train"]["is_phishing"],
        d["validation"][cols],
        d["validation"]["is_phishing"],
    )
    s_va = model.predict_proba(d["validation"][cols])[:, 1]
    y_va = d["validation"]["is_phishing"].to_numpy()
    thr = {t: threshold_for_fpr(s_va[y_va == 0], t) for t in TARGET_FPRS}
    res = evaluate(
        d["test"]["is_phishing"].to_numpy(), model.predict_proba(d["test"][cols])[:, 1], thr
    )
    res["shap_mean_abs"] = mean_abs_shap(model.get_booster(), d["test"][cols])
    print_result("Esperimento ingenuo: solo schema, www, percorso, parametri, lunghezza", res)
    print(
        "  feature più influenti (|SHAP| medio): "
        + ", ".join(f"{k} {v}" for k, v in res["shap_mean_abs"].items())
    )
    return res


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hosts", type=Path, default=DATA_DIR / "processed" / "hosts.parquet")
    parser.add_argument("--urls", type=Path, default=DATA_DIR / "processed" / "phiusiil.parquet")
    parser.add_argument("--out", type=Path, default=ARTIFACTS)
    args = parser.parse_args(argv)

    report, model, vocab = train_v1(pd.read_parquet(args.hosts))
    report["naive_full_url"] = naive_experiment(pd.read_parquet(args.urls))
    report["created"] = datetime.now(UTC).isoformat(timespec="seconds")

    args.out.mkdir(parents=True, exist_ok=True)
    model.save_model(args.out / "model-v1.json")
    (args.out / "suffix-vocab-v1.json").write_text(json.dumps(vocab, indent=1) + "\n")
    (args.out / "report-v1.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nModello, vocabolario e report salvati in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
