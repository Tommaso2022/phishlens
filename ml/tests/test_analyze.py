"""Test dello script di analisi su un modello addestrato con dati sintetici."""

import zipfile

import pytest
from phishlens_ml import analyze, build, train
from phishlens_ml.synthetic import synthetic_urls


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    d = tmp_path_factory.mktemp("analisi")
    urls = synthetic_urls(800)
    hosts = build.build(urls)
    hosts.to_parquet(d / "hosts.parquet")
    urls.to_parquet(d / "urls.parquet")
    args = ["--hosts", str(d / "hosts.parquet"), "--urls", str(d / "urls.parquet")]
    assert train.main([*args, "--out", str(d / "artifacts")]) == 0
    return d


def common(d):
    return ["--hosts", str(d / "hosts.parquet"), "--artifacts", str(d / "artifacts")]


@pytest.mark.parametrize(
    ("command", "expected"), [("suffix", "Suffisso"), ("errors", "Falsi positivi")]
)
def test_commands_run(setup, command, expected, capsys):
    assert analyze.main([command, *common(setup)]) == 0
    assert expected in capsys.readouterr().out


def test_tranco_with_local_archive(setup, capsys):
    raw = setup / "data" / "raw"
    raw.mkdir(parents=True)
    with zipfile.ZipFile(raw / "tranco-top-1m.zip", "w") as zf:
        zf.writestr("top-1m.csv", "1,unife.it\n2,esempio-nuovo.com\n3,paypal-verifica.xyz\n")
    args = [
        "tranco",
        *common(setup),
        "--data-dir",
        str(setup / "data"),
        "--manifest",
        str(setup / "manifest.json"),
        "--top",
        "10",
    ]
    assert analyze.main(args) == 0
    out = capsys.readouterr().out
    assert "unife[.]it" in out or "esempio-nuovo[.]com" in out
    assert "tranco-top-1m.zip" in (setup / "manifest.json").read_text()


def test_tranco_rejects_unexpected_archive(setup):
    d = setup / "altro"
    (d / "raw").mkdir(parents=True)
    with zipfile.ZipFile(d / "raw" / "tranco-top-1m.zip", "w") as zf:
        zf.writestr("leggimi.txt", "niente")
    args = ["tranco", *common(setup), "--data-dir", str(d), "--manifest", str(d / "m.json")]
    assert analyze.main(args) == 1
