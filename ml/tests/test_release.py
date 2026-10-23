import json

import pytest
from phishlens_core.integrity import verify_file
from phishlens_ml import build, release, train
from phishlens_ml.synthetic import synthetic_urls


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    d = tmp_path_factory.mktemp("rilascio")
    urls = synthetic_urls(400)
    build.build(urls).to_parquet(d / "hosts.parquet")
    urls.to_parquet(d / "urls.parquet")
    args = ["--hosts", str(d / "hosts.parquet"), "--urls", str(d / "urls.parquet")]
    assert train.main([*args, "--out", str(d / "artifacts"), "--version", "t1"]) == 0
    (d / "manifest.json").write_text(json.dumps({"phiusiil.zip": {"sha256": "ab" * 32}}))
    return d


def run(d):
    return release.main(
        [
            "t1",
            "--artifacts",
            str(d / "artifacts"),
            "--hosts",
            str(d / "hosts.parquet"),
            "--registry",
            str(d / "registry.json"),
            "--manifest",
            str(d / "manifest.json"),
        ]
    )


def test_release_records_hashes(trained):
    assert run(trained) == 0
    entry = json.loads((trained / "registry.json").read_text())["t1"]
    verify_file(trained / "artifacts" / "model-t1.json", entry["files"]["model-t1.json"])
    assert entry["datasets"] == {"phiusiil.zip": "ab" * 32}
    assert "train" in entry["data"]


def test_release_refuses_overwrite_with_different_files(trained):
    assert run(trained) == 0
    (trained / "artifacts" / "suffix-vocab-t1.json").write_text('["manomesso"]\n')
    assert run(trained) == 1
