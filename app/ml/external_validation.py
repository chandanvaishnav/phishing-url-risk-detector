import joblib
import pandas as pd

from app.features.url_features import extract_url_features


MODEL_FILE = "models/random_forest_url_all_features.joblib"
VALIDATION_FILE = "data/external/legitimate_validation.csv"


def main():
    print("\n" + "=" * 70)
    print("EXTERNAL LEGITIMATE URL VALIDATION")
    print("=" * 70)

    print("\nLoading model...")
    model = joblib.load(MODEL_FILE)

    print("Loading external validation data...")
    df = pd.read_csv(VALIDATION_FILE)

    print(f"Validation URLs: {len(df)}")

    # Extract the same 24 features used during training.
    X = pd.DataFrame(
        df["URL"].apply(
            extract_url_features
        ).tolist()
    )

    X = X[model.feature_names_in_]

    # Model prediction.
    predictions = model.predict(X)

    phishing_index = list(
        model.classes_
    ).index(0)

    phishing_probabilities = (
        model.predict_proba(X)[
            :, phishing_index
        ]
    )

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    results = pd.DataFrame(
        {
            "URL": df["URL"],
            "actual": df["label"],
            "predicted": predictions,
            "phishing_probability": (
                phishing_probabilities
            ),
        }
    )

    results["prediction"] = results[
        "predicted"
    ].map(
        {
            0: "phishing",
            1: "legitimate",
        }
    )

    print(
        results[
            [
                "URL",
                "prediction",
                "phishing_probability",
            ]
        ].to_string(index=False)
    )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    correct = (
        results["predicted"]
        == results["actual"]
    ).sum()

    total = len(results)

    accuracy = correct / total

    print("\n" + "=" * 70)
    print("EXTERNAL VALIDATION SUMMARY")
    print("=" * 70)

    print(
        f"Correct: {correct}/{total}"
    )

    print(
        f"External accuracy: {accuracy:.2%}"
    )

    print(
        "False positives:",
        (
            (
                (results["actual"] == 1)
                & (results["predicted"] == 0)
            )
            .sum()
        ),
    )

    output_file = (
        "data/processed/"
        "external_validation_results.csv"
    )

    results.to_csv(
        output_file,
        index=False,
    )

    print(
        f"\nResults saved to: {output_file}"
    )


if __name__ == "__main__":
    main()