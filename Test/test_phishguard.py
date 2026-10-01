import joblib

from fastapi.testclient import TestClient

import Backend.main as backend_main
from Backend.main import app
from app.features.url_features import extract_url_features


client = TestClient(app)


def test_model_feature_contract():
    model = joblib.load("models/random_forest_url_final.joblib")
    features = extract_url_features("https://google.com")
    assert list(model.feature_names_in_) == list(features.keys())


def test_sumit_feature_semantics_match_trained_url_pipeline():
    google_features = extract_url_features("https://google.com")
    synthetic_features = extract_url_features("https://paypal-login-security.example.com")

    assert google_features["NoOfOtherSpecialCharsInURL"] == 4
    assert synthetic_features["NoOfOtherSpecialCharsInURL"] == 7
    assert synthetic_features["NoOfSubDomain"] == 1
    assert synthetic_features["suspicious_keyword_count"] == 1


def test_scan_valid_url_returns_200():
    response = client.post("/api/v1/scan", json={"url": "https://google.com"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["url"] == "https://google.com"
    assert "classification" in payload
    assert "risk_score" in payload
    assert isinstance(payload["risk_score"], (int, float))
    assert payload["verdict"] == payload["classification"]
    assert isinstance(payload["confidence"], (int, float))
    assert isinstance(payload["dns"], dict)
    assert isinstance(payload["ssl"], dict)
    assert isinstance(payload["url_security"], dict)
    assert isinstance(payload["ml"], dict)
    assert isinstance(payload["signals"], list)
    assert isinstance(payload["explanation"], str)
    assert isinstance(payload["ir_analysis"], dict)
    assert payload["ir_analysis"]["status"] in {"available", "unavailable"}
    if payload["ir_analysis"]["status"] == "available":
        assert {"language_model", "pagerank", "content_recommendations"}.issubset(
            payload["ir_analysis"]
        )


def test_unresolvable_synthetic_url_is_not_safe():
    response = client.post(
        "/api/v1/scan",
        json={"url": "https://paypal-login-security.example.com/verify-account"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["verifiable"] is False
    assert payload["classification"] != "legitimate"
    assert payload["explanation"]


def test_scan_invalid_hostname_is_rejected():
    history_before = client.get("/api/v1/history").json()
    response = client.post("/api/v1/scan", json={"url": "hello"})
    assert response.status_code == 400, response.text
    payload = response.json()
    assert "Invalid URL" in str(payload.get("detail", payload))
    assert client.get("/api/v1/history").json() == history_before


def test_scan_malformed_url_is_rejected_without_history():
    history_before = client.get("/api/v1/history").json()
    response = client.post("/api/v1/scan", json={"url": "https://[::1"})

    assert response.status_code == 400, response.text
    assert client.get("/api/v1/history").json() == history_before


def test_ir_failure_does_not_fail_primary_scan(monkeypatch):
    class NoopConnection:
        def execute(self, *args):
            return None

        def commit(self):
            return None

        def close(self):
            return None

    def fail_ir(url):
        raise RuntimeError("simulated IR service failure")

    monkeypatch.setattr(backend_main, "validate_url", lambda url: True)
    monkeypatch.setattr(backend_main, "check_dns", lambda url: {"resolves": True})
    monkeypatch.setattr(backend_main, "check_ssl", lambda url: {"valid": True})
    monkeypatch.setattr(backend_main, "check_url_security", lambda url: {})
    monkeypatch.setattr(
        backend_main,
        "analyze_url",
        lambda url: {"classification": "legitimate", "phishing_probability": 0.1, "confidence": 0.9, "signals": []},
    )
    monkeypatch.setattr(
        backend_main,
        "calculate_risk",
        lambda **kwargs: {
            "risk_score": 6.0,
            "classification": "low_risk",
            "confidence": 0.9,
            "score_breakdown": {},
            "explanation": ["Primary scan completed."],
            "url_security_reasons": [],
        },
    )
    monkeypatch.setattr(backend_main, "analyze_url_with_ir", fail_ir)
    monkeypatch.setattr(backend_main, "get_connection", lambda: NoopConnection())

    response = client.post("/api/v1/scan", json={"url": "https://failure-test.example"})

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["classification"] == "legitimate"
    assert payload["risk_score"] == 6.0
    assert payload["ir_analysis"] == {
        "status": "unavailable",
        "message": "IR analysis temporarily unavailable",
    }
