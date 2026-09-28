def calculate_risk(
    ml_prediction: str,
    ml_probability: float,
    ml_confidence: float,
    dns_resolves: bool,
    ssl_valid: bool,
    url_security: dict
) -> dict:
    """
    Calculate the final hybrid phishing risk score.

    Score allocation:
        ML              = 60 points
        URL Security    = 20 points
        DNS             = 10 points
        SSL             = 10 points

    Maximum total score = 100.
    """

    ml_probability = max(
        0.0,
        min(1.0, float(ml_probability))
    )

    ml_confidence = max(
        0.0,
        min(1.0, float(ml_confidence))
    )

    # --------------------------------------------------
    # 1. ML SCORE (maximum 60 points)
    # --------------------------------------------------

    ml_score = ml_probability * 60

    # --------------------------------------------------
    # 2. URL SECURITY SCORE (maximum 20 points)
    # --------------------------------------------------

    url_security_score = 0
    url_security_reasons = []

    if url_security.get("has_ip_address", False):
        url_security_score += 5
        url_security_reasons.append("IP-based domain")

    if url_security.get("has_at_symbol", False):
        url_security_score += 4
        url_security_reasons.append("URL contains an @ symbol")

    if url_security.get("has_encoded_characters", False):
        url_security_score += 4
        url_security_reasons.append(
            "URL contains encoded characters"
        )

    if url_security.get("subdomain_count", 0) >= 3:
        url_security_score += 2
        url_security_reasons.append(
            "URL contains 3 or more subdomains"
        )

    if url_security.get("suspicious_keyword_count", 0) > 0:
        url_security_score += 2
        url_security_reasons.append(
            "URL contains suspicious keywords"
        )

    if url_security.get("url_length", 0) >= 100:
        url_security_score += 1
        url_security_reasons.append(
            "URL is unusually long"
        )

    if url_security.get("digit_count", 0) >= 5:
        url_security_score += 1
        url_security_reasons.append(
            "URL contains many digits"
        )

    url_security_score = min(url_security_score, 20)

    # --------------------------------------------------
    # 3. DNS SCORE (maximum 10 points)
    # --------------------------------------------------

    dns_score = 0

    if not dns_resolves:
        dns_score = 10

    # --------------------------------------------------
    # 4. SSL SCORE (maximum 10 points)
    # --------------------------------------------------

    ssl_score = 0

    if not ssl_valid:
        ssl_score = 10

    # --------------------------------------------------
    # 5. FINAL HYBRID SCORE
    # --------------------------------------------------

    risk_score = (
        ml_score
        + url_security_score
        + dns_score
        + ssl_score
    )

    risk_score = min(max(risk_score, 0), 100)

    # --------------------------------------------------
    # 6. FINAL RISK CLASSIFICATION
    # --------------------------------------------------

    if risk_score >= 60:
        classification = "high_risk"
    elif risk_score >= 30:
        classification = "medium_risk"
    else:
        classification = "low_risk"

    # --------------------------------------------------
    # 7. EXPLANATION
    # --------------------------------------------------

    explanation = []

    if ml_score > 0:
        explanation.append(
            f"ML contributed {ml_score:.2f}/60 points."
        )

    if url_security_reasons:
        explanation.append(
            "URL security indicators: "
            + ", ".join(url_security_reasons)
            + "."
        )

    if dns_score > 0:
        explanation.append(
            "DNS resolution failed, adding 10 risk points."
        )

    if ssl_score > 0:
        explanation.append(
            "SSL validation failed, adding 10 risk points."
        )

    if not explanation:
        explanation.append(
            "No significant risk indicators were detected."
        )

    return {
        "classification": classification,
        "risk_score": round(risk_score, 2),

        # Confidence represents confidence in the
        # selected ML classification.
        "confidence": round(ml_confidence, 6),

        "score_breakdown": {
            "ml": round(ml_score, 2),
            "url_security": url_security_score,
            "dns": dns_score,
            "ssl": ssl_score
        },

        "url_security_reasons": url_security_reasons,

        "explanation": explanation
    }