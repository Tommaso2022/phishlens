import pytest
from phishlens_core.integrity import IntegrityError, sha256_file, verify_file


def test_verify_accepts_matching_file(tmp_path):
    f = tmp_path / "model.json"
    f.write_text('{"albero": 1}')
    verify_file(f, sha256_file(f))


def test_verify_rejects_tampered_file(tmp_path):
    f = tmp_path / "model.json"
    f.write_text('{"albero": 1}')
    expected = sha256_file(f)
    f.write_text('{"albero": 2}')
    with pytest.raises(IntegrityError):
        verify_file(f, expected)
