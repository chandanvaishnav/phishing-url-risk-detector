import joblib
import pandas as pd
import shap

from app.features.url_features import extract_url_features


MODEL_FILE = "models/random_forest_url_all_features.joblib"


def explain_url(url: str):
    """
    Generate an ML prediction and SHAP explanation for a URL.
    """

    # --------------------------------------------------
    # 1. Load model
    # --------------------------------------------------

    model = joblib.load(MODEL_FILE)

    # --------------------------------------------------
    # 2. Extract URL features
    # --------------------------------------------------

    features = extract_url_features(url)

    feature_df = pd.DataFrame(
        [features]
    )

    # --------------------------------------------------
    # 3. Keep only the features expected by the model
    # --------------------------------------------------

    model_features = model.feature_names_in_

    feature_df = feature_df[
        model_features
    ]

    # --------------------------------------------------
    # 4. Model prediction
    # --------------------------------------------------

    probabilities = model.predict_proba(
        feature_df
    )[0]

    prediction = model.predict(
        feature_df
    )[0]

    # --------------------------------------------------
    # 5. Phishing probability
    #
    # Model classes:
    # 0 = phishing
    # 1 = legitimate
    # --------------------------------------------------

    phishing_index = list(
        model.classes_
    ).index(0)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    # --------------------------------------------------
    # 6. SHAP explanation
    # --------------------------------------------------

    explainer = shap.TreeExplainer(
        model
    )

    shap_values = explainer.shap_values(
        feature_df
    )

    # --------------------------------------------------
    # 7. Extract phishing SHAP values
    # --------------------------------------------------

    # SHAP 0.52+ may return a 3D array:
# (samples, features, classes)

    if isinstance(shap_values, list):
        phishing_shap = shap_values[
            phishing_index
        ][0]

    elif getattr(shap_values, "ndim", 0) == 3:
        phishing_shap = shap_values[
            0,
            :,
            phishing_index
        ]

    else:
        phishing_shap = shap_values[0]

    # --------------------------------------------------
    # 8. Rank important features
    # --------------------------------------------------

    explanation = []

    for feature_name, shap_value, feature_value in zip(
        model_features,
        phishing_shap,
        feature_df.iloc[0].values,
    ):
        explanation.append(
            {
                "feature": feature_name,
                "value": float(feature_value),
                "impact": float(
                    getattr(shap_value, "item", lambda: shap_value)()
                    ),
            }
        )

    explanation.sort(
        key=lambda item: abs(
            item["impact"]
        ),
        reverse=True,
    )

    # --------------------------------------------------
    # 9. Final result
    # --------------------------------------------------

    result = {
        "prediction": (
            "phishing"
            if prediction == 0
            else "legitimate"
        ),
        "phishing_probability": phishing_probability,
        "important_features": explanation[:10],
    }

    return result


# ------------------------------------------------------
# Test
# ------------------------------------------------------

if __name__ == "__main__":

    test_url = "https://example.com"

    result = explain_url(
        test_url
    )

    print("\n" + "=" * 60)
    print("SHAP URL EXPLANATION")
    print("=" * 60)

    print(
        "URL:",
        test_url
    )

    print(
        "Prediction:",
        result["prediction"]
    )

    print(
        "Phishing probability:",
        round(
            result[
                "phishing_probability"
            ],
            4,
        ),
    )

    print("\nTop important features:")

    for item in result[
        "important_features"
    ]:

        print(
            f"{item['feature']}: "
            f"value={item['value']}, "
            f"impact={item['impact']:.6f}"
        )