import json
import threading
import warnings
from pathlib import Path

import joblib
import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_FILE = PROJECT_ROOT / "models" / "random_forest_url_final.joblib"
THRESHOLD = 0.95
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

_MODEL = None
_MODEL_LOCK = threading.Lock()


def _get_model():
    """Lazily load and reuse the trained model across requests."""
    global _MODEL

    if _MODEL is None:
        with _MODEL_LOCK:
            if _MODEL is None:
                _MODEL = joblib.load(MODEL_FILE, mmap_mode="r")

    return _MODEL


def generate_ml_evidence(url):
    """
    Generate ML-based risk evidence for a URL.

    Model convention:
        0 = phishing
        1 = legitimate

    Important:
        This module provides ML evidence only.
        It does NOT claim that a URL is 100% safe.
    """

    # ---------------------------------------------------------
    # Load final model once and reuse it
    # ---------------------------------------------------------

    model = _get_model()

    # ---------------------------------------------------------
    # Extract URL features
    # ---------------------------------------------------------

    from app.features.url_features import extract_url_features

    feature_dict = extract_url_features(url)

    if hasattr(model, "feature_names_in_"):
        model_features = list(model.feature_names_in_)
        ordered_values = [float(feature_dict.get(feature_name, 0.0)) for feature_name in model_features]
        X = np.asarray([ordered_values], dtype=np.float64)
    else:
        ordered_values = [float(value) for value in feature_dict.values()]
        X = np.asarray([ordered_values], dtype=np.float64)

    # ---------------------------------------------------------
    # Prediction
    # ---------------------------------------------------------

    probabilities = model.predict_proba(X)[0]

    classes = list(model.classes_)

    phishing_index = classes.index(0)
    legitimate_index = classes.index(1)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    legitimate_probability = float(
        probabilities[legitimate_index]
    )

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    if phishing_probability >= THRESHOLD:
        classification = "phishing"
    else:
        classification = "legitimate"

    # ---------------------------------------------------------
    # Confidence
    #
    # We expose the probability corresponding to the
    # selected class.
    # ---------------------------------------------------------

    if classification == "phishing":
        confidence = phishing_probability
    else:
        confidence = legitimate_probability

    # ---------------------------------------------------------
    # ML signals
    #
    # These are structural indicators from the URL features.
    # They are evidence, NOT proof of maliciousness.
    # ---------------------------------------------------------

    signals = []

    if feature_dict["IsHTTPS"] == 0:
        signals.append({
            "signal": "no_https",
            "description": "URL does not use HTTPS.",
            "severity": "medium"
        })

    if feature_dict["IsDomainIP"] == 1:
        signals.append({
            "signal": "ip_based_domain",
            "description": "URL uses an IP address instead of a normal domain.",
            "severity": "high"
        })

    if feature_dict["NoOfSubDomain"] >= 3:
        signals.append({
            "signal": "many_subdomains",
            "description": "URL contains multiple subdomain levels.",
            "severity": "medium"
        })

    if feature_dict["has_at_symbol"] == 1:
        signals.append({
            "signal": "at_symbol",
            "description": "URL contains an @ symbol.",
            "severity": "high"
        })

    if feature_dict["has_hyphen_in_domain"] == 1:
        signals.append({
            "signal": "hyphen_in_domain",
            "description": "Domain contains a hyphen.",
            "severity": "low"
        })

    if feature_dict["HasObfuscation"] == 1:
        signals.append({
            "signal": "url_obfuscation",
            "description": "URL contains encoded or obfuscated characters.",
            "severity": "high"
        })

    if feature_dict["suspicious_keyword_count"] > 0:
        signals.append({
            "signal": "suspicious_keywords",
            "description": (
                "URL contains security-related keywords "
                "such as login, verify, secure or account."
            ),
            "severity": "medium"
        })

    if feature_dict["URLLength"] >= 100:
        signals.append({
            "signal": "long_url",
            "description": "URL is unusually long.",
            "severity": "medium"
        })

    if feature_dict["NoOfDegitsInURL"] >= 5:
        signals.append({
            "signal": "many_digits",
            "description": "URL contains a relatively high number of digits.",
            "severity": "low"
        })

    # ---------------------------------------------------------
    # Evidence level
    # ---------------------------------------------------------

    if phishing_probability >= 0.95:
        ml_evidence_level = "high"
    elif phishing_probability >= 0.50:
        ml_evidence_level = "medium"
    else:
        ml_evidence_level = "low"

    # ---------------------------------------------------------
    # Human-readable explanation
    # ---------------------------------------------------------

    if classification == "phishing":

        explanation = (
            "The ML model assigns a high phishing probability "
            "to this URL based on its URL structure and "
            "learned patterns. Additional security signals "
            "should be checked before making a final risk decision."
        )

    else:

        explanation = (
            "The ML model does not classify this URL as phishing "
            "at the locked threshold. This is ML evidence only "
            "and does not guarantee that the URL is safe."
        )

    # ---------------------------------------------------------
    # Final ML evidence object
    # ---------------------------------------------------------

    result = {
        "classification": classification,

        "phishing_probability": round(
            phishing_probability,
            6
        ),

        "legitimate_probability": round(
            legitimate_probability,
            6
        ),

        "confidence": round(
            confidence,
            6
        ),

        "threshold": THRESHOLD,

        "ml_evidence_level": ml_evidence_level,

        "signals": signals,

        "explanation": explanation
    }

    return result


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    url = input(
        "\nEnter URL for ML risk analysis: "
    ).strip()

    if not url:

        print("No URL entered.")

    else:

        result = generate_ml_evidence(url)

        print("\n" + "=" * 70)
        print("ML RISK EVIDENCE")
        print("=" * 70)

        print(
            json.dumps(
                result,
                indent=4
            )
        )

        print("=" * 70)