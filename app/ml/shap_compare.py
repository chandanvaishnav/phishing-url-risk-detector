import pandas as pd
import joblib
import shap

from app.features.url_features import extract_url_features


MODEL_FILE = "models/random_forest_url_all_features.joblib"


def get_shap_result(model, url):
    features = extract_url_features(url)

    X = pd.DataFrame([features])
    X = X[model.feature_names_in_]

    probabilities = model.predict_proba(X)[0]

    phishing_index = list(model.classes_).index(0)

    phishing_probability = probabilities[phishing_index]

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    if isinstance(shap_values, list):
        values = shap_values[phishing_index][0]

    elif getattr(shap_values, "ndim", 0) == 3:
        values = shap_values[0, :, phishing_index]

    else:
        values = shap_values[0]

    result = []

    for feature, value, impact in zip(
        model.feature_names_in_,
        X.iloc[0].values,
        values,
    ):
        result.append(
            {
                "feature": feature,
                "value": float(value),
                "impact": float(
                    getattr(
                        impact,
                        "item",
                        lambda: impact,
                    )()
                ),
            }
        )

    result.sort(
        key=lambda x: abs(x["impact"]),
        reverse=True,
    )

    return phishing_probability, result


def main():

    model = joblib.load(MODEL_FILE)

    # One external legitimate URL
    external_url = "https://example.com"

    # One legitimate URL from our dataset
    dataset_url = "https://www.uni-mainz.de"

    for url in [external_url, dataset_url]:

        probability, explanation = get_shap_result(
            model,
            url,
        )

        print("\n" + "=" * 70)
        print("URL:", url)
        print(
            "Phishing probability:",
            round(probability, 6),
        )

        print("\nTop 10 SHAP features:")

        for item in explanation[:10]:

            print(
                f"{item['feature']:<30} "
                f"value={item['value']:<10.4f} "
                f"impact={item['impact']:+.6f}"
            )


if __name__ == "__main__":
    main()