"""Test dello script di download e preparazione di PhiUSIIL.

Usano un archivio sintetico con la stessa struttura di quello di UCI e
domini riservati ai test (.test, example.com): nessun URL reale.
"""

import json
import zipfile
from pathlib import Path

import pandas as pd
import pytest
from phishlens_ml import datasets as ds

MEMBER = ds.SOURCE["csv_member"]
CSV = (
    "FILENAME,URL,URLLength,label\n"
    "a.txt,https://www.example.com/,24,1\n"
    "b.txt,http://login-verify.test/account,32,0\n"
    "c.txt,  http://login-verify.test/account  ,32,0\n"  # duplicato con spazi
    "d.txt,http://conflitto.test/,22,0\n"
    "e.txt,http://conflitto.test/,22,1\n"  # stesso URL, etichette diverse
    f"f.txt,http://lungo.test/{'a' * 3000},3000,0\n"  # oltre 2048 caratteri
)


def make_zip(path: Path, content: str = CSV, member: str = MEMBER) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, content)
    return path


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    (data / "raw").mkdir(parents=True)
    make_zip(data / "raw" / "phiusiil.zip")
    return data, tmp_path / "manifest.json"


def run(data, manifest):
    return ds.main(["--data-dir", str(data), "--manifest", str(manifest)])


def test_first_run_records_hashes_and_prepares_data(env):
    data, manifest = env
    assert run(data, manifest) == 0
    recorded = json.loads(manifest.read_text())
    assert set(recorded) == {"phiusiil.zip", "phiusiil.csv"}
    assert recorded["phiusiil.zip"]["license"] == "CC BY 4.0"

    df = pd.read_parquet(data / "processed" / "phiusiil.parquet")
    assert list(df.columns) == ["url", "is_phishing"]
    assert sorted(df["url"]) == ["http://login-verify.test/account", "https://www.example.com/"]
    labels = dict(zip(df["url"], df["is_phishing"], strict=True))
    assert labels["https://www.example.com/"] == 0  # label 1 in PhiUSIIL = legittimo
    assert labels["http://login-verify.test/account"] == 1


def test_second_run_verifies_hash(env, capsys):
    data, manifest = env
    assert run(data, manifest) == 0
    assert run(data, manifest) == 0
    assert "[ok] phiusiil.zip" in capsys.readouterr().out


def test_tampered_archive_is_rejected(env):
    data, manifest = env
    assert run(data, manifest) == 0
    make_zip(data / "raw" / "phiusiil.zip", CSV + "g.txt,http://nuovo.test/,19,0\n")
    assert run(data, manifest) == 1


def test_zip_slip_path_is_ignored(tmp_path, env):
    data, manifest = env
    make_zip(data / "raw" / "phiusiil.zip", member=f"../../fuori/{MEMBER}")
    assert run(data, manifest) == 0
    assert not (tmp_path / "fuori").exists()
    assert (data / "raw" / MEMBER).exists()


def test_zip_bomb_is_rejected(env):
    data, manifest = env
    bomb = "FILENAME,URL,label\n" + "x.txt,http://a.test/,1\n" * 200_000
    make_zip(data / "raw" / "phiusiil.zip", bomb)
    assert run(data, manifest) == 1
    assert not (data / "processed" / "phiusiil.parquet").exists()


def test_unexpected_columns_are_rejected(env):
    data, manifest = env
    make_zip(data / "raw" / "phiusiil.zip", "FILENAME,Link,Class\na.txt,http://a.test/,1\n")
    assert run(data, manifest) == 1


def test_only_https_downloads(tmp_path):
    with pytest.raises(ds.DatasetError):
        ds.download("http://archive.ics.uci.edu/x.zip", tmp_path / "x.zip")
