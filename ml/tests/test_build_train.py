"""Test end-to-end su dati sintetici: costruzione del dataset e addestramento."""

import json
import zipfile

import pandas as pd
import pytest
from phishlens_ml import build, train
from phishlens_ml.synthetic import synthetic_urls

TRANCO_NAMES = [
    "google.com",  # senza sottodominio: ignorato
    "it.wikipedia.org",
    "mail.esempio-uno.com",
    "progetto.github.io",  # piattaforma condivisa: ignorato
    "login.paypal-verifica-123.xyz",  # dominio presente tra il phishing: ignorato
]


@pytest.fixture(scope="module")
def hosts():
    urls = synthetic_urls()
    urls.loc[len(urls)] = ("http://paypal-verifica-123.xyz/", 1)
    return build.build(urls, TRANCO_NAMES)


def test_no_registered_domain_in_two_splits(hosts):
    assert hosts.groupby("registered_domain")["split"].nunique().max() == 1


def test_shared_platforms_removed(hosts):
    assert not hosts["host"].str.endswith((".ipfs.io", ".web.app", ".github.io")).any()


def test_phishing_on_legit_domain_removed(hosts):
    same_domain = hosts["registered_domain"] == "esempio-legittimo.com"
    assert same_domain.any()
    assert not (same_domain & (hosts["is_phishing"] == 1)).any()


def test_tranco_subdomains_added_as_legit(hosts):
    tranco = hosts[hosts["source"] == "tranco"]
    assert set(tranco["host"]) == {"it.wikipedia.org", "mail.esempio-uno.com"}
    assert (tranco["is_phishing"] == 0).all()


def test_www_never_in_hosts(hosts):
    assert not hosts["host"].str.startswith("www.").any()


def test_build_main_with_local_tranco_archive(tmp_path):
    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    with zipfile.ZipFile(raw / "tranco-top-1m-subdomains.zip", "w") as zf:
        zf.writestr("top-1m.csv", "1,it.wikipedia.org\n2,mail.esempio-uno.com\n")
    synthetic_urls(200).to_parquet(tmp_path / "urls.parquet")
    args = [
        "--input",
        str(tmp_path / "urls.parquet"),
        "--output",
        str(tmp_path / "hosts.parquet"),
        "--data-dir",
        str(tmp_path / "data"),
        "--manifest",
        str(tmp_path / "manifest.json"),
    ]
    assert build.main(args) == 0
    assert "tranco-top-1m-subdomains.zip" in (tmp_path / "manifest.json").read_text()
    assert (pd.read_parquet(tmp_path / "hosts.parquet")["source"] == "tranco").sum() == 2


def test_training_end_to_end(tmp_path, hosts):
    urls = synthetic_urls()
    hosts.to_parquet(tmp_path / "hosts.parquet")
    urls.to_parquet(tmp_path / "urls.parquet")
    out = tmp_path / "artifacts"
    args = ["--hosts", str(tmp_path / "hosts.parquet"), "--urls", str(tmp_path / "urls.parquet")]
    assert train.main([*args, "--out", str(out), "--version", "prova"]) == 0
    report = json.loads((out / "report-prova.json").read_text())
    assert {"logistic_regression", "xgboost", "naive_full_url"} <= set(report)
    assert (out / "model-prova.json").exists()
    for point in report["xgboost"]["operating_points"]:
        assert 0 <= point["fpr"] <= 1
        assert "fpr_legit_with_subdomain" in point


def test_threshold_respects_fpr():
    legit = pd.Series(range(1000)).to_numpy() / 1000
    thr = train.threshold_for_fpr(legit, 0.01)
    assert (legit > thr).mean() <= 0.01
