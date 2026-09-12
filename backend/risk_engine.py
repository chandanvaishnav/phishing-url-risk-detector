def calculate_risk(
    ml_prediction: str,
    ml_probability: float,
    dns_resolves: bool,
    ssl_valid: bool,
    url_security: dict
) -> dict:

    return {
        "classification": "pending",
        "risk_score": None,
        "confidence": ml_probability,
        "explanation": []
    }