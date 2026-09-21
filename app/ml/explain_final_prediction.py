from pathlib import Path

import joblib
import pandas as pd
import shap


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_final.joblib"
)


def explain_url(url):
    """
    Generate an ML prediction and SHAP explanation
    for a single URL.

    Model convention:
        0 = phishing
        1 = legitimate
    """

    # ---------------------------------------------------------
    # Load model
    # ---------------------------------------------------------

    model = joblib.load(MODEL_FILE)

    # ---------------------------------------------------------
    # Extract URL features
    # ---------------------------------------------------------

    from app.features.url_features import extract_url_features

    feature_dict = extract_url_features(url)

    features = pd.DataFrame(
        [feature_dict]
    )

    X = features.drop(
        columns=["label"],
        errors="ignore"
    )

    # ---------------------------------------------------------
    # Verify feature order
    # ---------------------------------------------------------

    if hasattr(model, "feature_names_in_"):

        model_features = list(
            model.feature_names_in_
        )

        current_features = list(
            X.columns
        )

        if model_features != current_features:

            raise ValueError(
                "Feature mismatch!\n\n"
                f"Model features:\n{model_features}\n\n"
                f"Current features:\n{current_features}"
            )

    # ---------------------------------------------------------
    # Prediction
    # ---------------------------------------------------------

    probabilities = model.predict_proba(X)[0]

    classes = list(model.classes_)

    phishing_index = classes.index(0)
    legitimate_index = classes.index(1)

    phishing_probability = (
        probabilities[phishing_index]
    )

    legitimate_probability = (
        probabilities[legitimate_index]
    )

    # Locked final threshold
    threshold = 0.95

    if phishing_probability >= threshold:
        prediction = "phishing"
    else:
        prediction = "legitimate"

    # ---------------------------------------------------------
    # SHAP TreeExplainer
    # ---------------------------------------------------------

    print("\nCalculating SHAP explanation...")

    explainer = shap.TreeExplainer(model)

    shap_values = explainer.shap_values(X)

    # SHAP output differs between SHAP versions.
    #
    # For binary Random Forest:
    #   Sometimes:
    #       list[class][sample][feature]
    #
    #   Sometimes:
    #       sample x feature x class
    #
    # Handle both formats.
    # ---------------------------------------------------------

    if isinstance(shap_values, list):

        # Class 0 = phishing
        values = shap_values[phishing_index][0]

    else:

        shap_array = shap_values

        if shap_array.ndim == 3:

            # sample, feature, class
            values = shap_array[
                0,
                :,
                phishing_index
            ]

        elif shap_array.ndim == 2:

            values = shap_array[0]

        else:

            values = shap_array

    # ---------------------------------------------------------
    # Create feature explanation table
    # ---------------------------------------------------------

    explanation_df = pd.DataFrame({
        "feature": X.columns,
        "value": X.iloc[0].values,
        "impact": values
    })

    # Absolute impact tells us which features had
    # the largest influence.
    explanation_df["absolute_impact"] = (
        explanation_df["impact"].abs()
    )

    explanation_df = explanation_df.sort_values(
        "absolute_impact",
        ascending=False
    )

    # ---------------------------------------------------------
    # Print result
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL MODEL — SHAP EXPLANATION")
    print("=" * 70)

    print(f"\nURL:")
    print(url)

    print(
        f"\nPrediction: {prediction.upper()}"
    )

    print(
        f"Phishing probability: "
        f"{phishing_probability:.6f}"
    )

    print(
        f"Legitimate probability: "
        f"{legitimate_probability:.6f}"
    )

    print(
        f"Locked threshold: "
        f"{threshold:.2f}"
    )

    print("\nTop contributing features:")

    print(
        explanation_df[
            [
                "feature",
                "value",
                "impact"
            ]
        ]
        .head(10)
        .to_string(index=False)
    )

    # ---------------------------------------------------------
    # Human-readable explanation
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("INTERPRETATION")
    print("=" * 70)

    top_features = explanation_df.head(5)

    for _, row in top_features.iterrows():

        direction = (
            "increased"
            if row["impact"] > 0
            else "decreased"
        )

        print(
            f"- {row['feature']} "
            f"(value={row['value']}) "
            f"{direction} the model's phishing score."
        )

    print("\nNote:")
    print(
        "SHAP explains the model's decision; "
        "it does not prove that a feature causes phishing."
    )

    print("=" * 70)

    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability": float(
            phishing_probability
        ),
        "legitimate_probability": float(
            legitimate_probability
        ),
        "threshold": threshold,
        "important_features":
            explanation_df[
                [
                    "feature",
                    "value",
                    "impact"
                ]
            ]
            .head(10)
            .to_dict(orient="records")
    }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    test_url = input(
        "\nEnter URL to explain: "
    ).strip()

    if not test_url:
        print("No URL entered.")
    else:
        explain_url(test_url)