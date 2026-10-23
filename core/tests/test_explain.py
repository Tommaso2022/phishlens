from phishlens_core.explain import describe, top_reasons


def test_risk_and_safe_texts():
    assert "phishing" in describe("suffix", "xyz", 1.2)
    assert "legittimi" in describe("suffix", "it", -0.8)
    assert describe("sconosciuta", 3, 0.5) == "sconosciuta = 3"


def test_top_reasons_order_and_direction():
    features = {"suffix": "xyz", "n_hyphens": 2, "host_length": 9}
    contrib = {"suffix": 1.5, "n_hyphens": 0.4, "host_length": -0.7}
    risk = top_reasons(features, contrib, k=2)
    assert [r.feature for r in risk] == ["suffix", "n_hyphens"]
    safe = top_reasons(features, contrib, direction="safe")
    assert [r.feature for r in safe] == ["host_length"]


def test_texts_never_contain_the_domain():
    features = {"suffix": "com", "host_length": 20}
    for r in top_reasons(features, {"suffix": 1.0, "host_length": 0.5}):
        assert "paypal" not in r.text
