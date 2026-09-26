def calculate_risk(
    ml_prediction: str,
    ml_probability: float,
    ml_confidence: float,
    dns_resolves: bool,
    ssl_valid: bool,
    url_security: dict
) -> dict:
    """
    Calculate final phishing risk using a hybrid scoring model.

    Weight distribution:
        ML evidence       = 60 points
        DNS evidence      = 10 points
        SSL evidence      = 10 points
        URL security      = 20 points

    Final risk score:
        0   = lowest risk
        100 = highest risk

    Confidence:
        Uses the ML service confidence for consistency
        with the project's ML evidence.
    """

    explanation = []

    # --------------------------------------------------
    # 1. ML SCORE - 60 points
    # --------------------------------------------------

    ml_score = ml_probability * 60

    if ml_prediction == "phishing":
        explanation.append(
            "ML model detected a high phishing probability."
        )
    else:
        explanation.append(
            "ML model did not classify the URL as phishing "
            "at the configured threshold."
        )

    # --------------------------------------------------
    # 2. DNS SCORE - 10 points
    # --------------------------------------------------

    if dns_resolves:
        dns_score = 0
        explanation.append(
            "Domain successfully resolves through DNS."
        )
    else:
        dns_score = 10
        explanation.append(
            "Domain could not be resolved through DNS."
        )

    # --------------------------------------------------
    # 3. SSL SCORE - 10 points
    # --------------------------------------------------

    if ssl_valid:
        ssl_score = 0
        explanation.append(
            "SSL certificate verification succeeded."
        )
    else:
        ssl_score = 10
        explanation.append(
            "SSL certificate verification failed."
        )

    # --------------------------------------------------
    # 4. URL SECURITY SCORE - 20 points
    # --------------------------------------------------

    url_score = 0

    if url_security.get("has_ip_address"):
        url_score += 5
        explanation.append(
            "URL uses an IP address instead of a normal domain."
        )

    if url_security.get("has_at_symbol"):
        url_score += 5
        explanation.append(
            "URL contains an @ symbol."
        )

    if url_security.get("has_suspicious_symbol"):
        url_score += 3
        explanation.append(
            "URL contains a potentially suspicious symbol."
        )

    if url_security.get("suspicious_keyword_count", 0) > 0:
        url_score += 3
        explanation.append(
            "URL contains security-related keywords."
        )

    if url_security.get("has_encoded_characters"):
        url_score += 2
        explanation.append(
            "URL contains encoded characters."
        )

    if url_security.get("subdomain_count", 0) >= 3:
        url_score += 2
        explanation.append(
            "URL contains multiple subdomain levels."
        )

    # Keep URL security contribution within its 20-point limit.
    url_score = min(url_score, 20)

    # --------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------

    risk_score = ml_score + dns_score + ssl_score + url_score

    risk_score = round(
        min(max(risk_score, 0), 100),
        2
    )

    # --------------------------------------------------
    # FINAL CLASSIFICATION
    # --------------------------------------------------

    if risk_score >= 70:
        classification = "high_risk"
    elif risk_score >= 40:
        classification = "suspicious"
    else:
        classification = "low_risk"

    # --------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------

    confidence = round(
        ml_confidence,
        6
    )

    return {
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "explanation": explanation
    }
