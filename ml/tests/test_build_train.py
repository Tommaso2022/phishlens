"""Test end-to-end su dati sintetici: costruzione del dataset e addestramento."""

import json

import pandas as pd
import pytest
from phishlens_ml import build, train
from phishlens_ml.synthetic import synthetic_urls


@pytest.fixture(scope="module")
def hosts():
    return build.build(synthetic_urls())


def test_no_registered_domain_in_two_splits(hosts):
    per_domain = hosts.groupby("registered_domain")["split"].nunique()
    assert per_domain.max() == 1


def test_platform_hosted_phishing_removed(hosts):
    assert "ipfs.io" not in set(hosts["registered_domain"])
    same_domain = hosts["registered_domain"] == "esempio-legittimo.com"
    assert same_domain.any()
    assert not (same_domain & (hosts["is_phishing"] == 1)).any()


def test_www_never_in_hosts(hosts):
    assert not hosts["host"].str.startswith("www.").any()


def test_training_end_to_end(tmp_path, hosts):
    urls = synthetic_urls()
    hosts.to_parquet(tmp_path / "hosts.parquet")
    urls.to_parquet(tmp_path / "urls.parquet")
    out = tmp_path / "artifacts"
    args = ["--hosts", str(tmp_path / "hosts.parquet"), "--urls", str(tmp_path / "urls.parquet")]
    assert train.main([*args, "--out", str(out)]) == 0
    report = json.loads((out / "report-v1.json").read_text())
    assert {"logistic_regression", "xgboost", "naive_full_url"} <= set(report)
    assert (out / "model-v1.json").exists()
    for point in report["xgboost"]["operating_points"]:
        assert 0 <= point["fpr"] <= 1


def test_threshold_respects_fpr():
    legit = pd.Series(range(1000)).to_numpy() / 1000
    thr = train.threshold_for_fpr(legit, 0.01)
    assert (legit > thr).mean() <= 0.01
