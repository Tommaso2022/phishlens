import pytest
from phishlens_core.explain import FACTS, describe, top_reasons
from phishlens_core.features import NUMERIC_FEATURES


def test_suffix_depends_on_direction():
    assert "phishing" in describe("suffix", "xyz", 1.2)
    assert "legittimi" in describe("suffix", "it", -0.8)


@pytest.mark.parametrize(
    ("feature", "value", "expected"),
    [
        ("n_labels", 2, "Il nome ha 2 parti separate da punti"),
        ("n_subdomain_labels", 0, "Nessun sottodominio"),
        ("n_subdomain_labels", 1, "Un sottodominio"),
        ("n_digits", 6, "6 cifre"),
        ("n_hyphens", 0, "Nessun trattino"),
        ("is_punycode", 0, "Solo caratteri latini standard"),
    ],
)
def test_facts_match_the_value(feature, value, expected):
    # La stessa frase, qualunque sia la direzione del contributo.
    assert describe(feature, value, 0.7) == expected
    assert describe(feature, value, -0.7) == expected


def test_no_judgement_words_for_small_values():
    for c in (1.0, -1.0):
        text = describe("n_labels", 2, c) + describe("n_subdomain_labels", 0, c)
        assert "molt" not in text.lower()


def test_every_numeric_feature_has_a_text():
    assert set(NUMERIC_FEATURES) <= set(FACTS) | {"entropy"}


def test_top_reasons_order_and_direction():
    features = {"suffix": "xyz", "n_hyphens": 2, "host_length": 9}
    contrib = {"suffix": 1.5, "n_hyphens": 0.4, "host_length": -0.7}
    assert [r.feature for r in top_reasons(features, contrib, k=2)] == ["suffix", "n_hyphens"]
    assert [r.feature for r in top_reasons(features, contrib, direction="safe")] == ["host_length"]


def test_unknown_feature():
    assert describe("sconosciuta", 3, 0.5) == "sconosciuta = 3"
