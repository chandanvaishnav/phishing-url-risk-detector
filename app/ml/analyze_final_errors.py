from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_final.joblib"
)

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_strict_external_test.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "error_analysis"
)

THRESHOLD = 0.95


def main():

    print("=" * 70)
    print("FINAL MODEL — ERROR ANALYSIS")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load model
    # ---------------------------------------------------------

    print("\nLoading final model...")

    model = joblib.load(MODEL_FILE)

    # ---------------------------------------------------------
    # Load strict external test
    # ---------------------------------------------------------

    print("Loading strict external test...")

    df = pd.read_csv(TEST_FILE)

    print(f"Test URLs: {len(df):,}")

    # ---------------------------------------------------------
    # Feature extraction
    # ---------------------------------------------------------

    from app.features.url_features import extract_url_features

    print("\nExtracting features...")

    feature_rows = df["URL"].apply(
        extract_url_features
    )

    features_df = pd.DataFrame(
        feature_rows.tolist()
    )

    X = features_df.drop(
        columns=["label"],
        errors="ignore"
    )

    y_true = df["label"].astype(int)

    # ---------------------------------------------------------
    # Prediction
    # ---------------------------------------------------------

    print("Generating predictions...")

    probabilities = model.predict_proba(X)

    phishing_index = list(
        model.classes_
    ).index(0)

    phishing_probability = probabilities[
        :, phishing_index
    ]

    y_pred = (
        phishing_probability < THRESHOLD
    ).astype(int)

    # ---------------------------------------------------------
    # Add prediction information
    # ---------------------------------------------------------

    results = df.copy()

    results["phishing_probability"] = (
        phishing_probability
    )

    results["predicted_label"] = y_pred

    # ---------------------------------------------------------
    # Identify errors
    #
    # Label 0 = phishing
    # Label 1 = legitimate
    # ---------------------------------------------------------

    false_negatives = results[
        (results["label"] == 0)
        &
        (results["predicted_label"] == 1)
    ].copy()

    false_positives = results[
        (results["label"] == 1)
        &
        (results["predicted_label"] == 0)
    ].copy()

    true_positives = results[
        (results["label"] == 0)
        &
        (results["predicted_label"] == 0)
    ]

    true_negatives = results[
        (results["label"] == 1)
        &
        (results["predicted_label"] == 1)
    ]

    # ---------------------------------------------------------
    # Create output directory
    # ---------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # ---------------------------------------------------------
    # Save errors
    # ---------------------------------------------------------

    fn_file = (
        OUTPUT_DIR
        / "false_negatives.csv"
    )

    fp_file = (
        OUTPUT_DIR
        / "false_positives.csv"
    )

    false_negatives.to_csv(
        fn_file,
        index=False
    )

    false_positives.to_csv(
        fp_file,
        index=False
    )

    # ---------------------------------------------------------
    # Probability statistics
    # ---------------------------------------------------------

    fn_probability = (
        false_negatives["phishing_probability"]
    )

    fp_probability = (
        false_positives["phishing_probability"]
    )

    # ---------------------------------------------------------
    # Print summary
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ERROR SUMMARY")
    print("=" * 70)

    print(
        f"\nFalse Negatives : "
        f"{len(false_negatives)}"
    )

    print(
        f"False Positives : "
        f"{len(false_positives)}"
    )

    print(
        f"True Positives  : "
        f"{len(true_positives)}"
    )

    print(
        f"True Negatives  : "
        f"{len(true_negatives)}"
    )

    # ---------------------------------------------------------
    # False Negative analysis
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FALSE NEGATIVES")
    print("Actual phishing → predicted legitimate")
    print("=" * 70)

    if len(false_negatives) > 0:

        print(
            "\nPhishing probability statistics:"
        )

        print(
            f"Mean   : {fn_probability.mean():.6f}"
        )

        print(
            f"Median : {fn_probability.median():.6f}"
        )

        print(
            f"Minimum: {fn_probability.min():.6f}"
        )

        print(
            f"Maximum: {fn_probability.max():.6f}"
        )

        print("\nSample false negatives:")

        print(
            false_negatives[
                [
                    "URL",
                    "phishing_probability"
                ]
            ]
            .sort_values(
                "phishing_probability",
                ascending=False
            )
            .head(30)
            .to_string(index=False)
        )

    # ---------------------------------------------------------
    # False Positive analysis
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FALSE POSITIVES")
    print("Actual legitimate → predicted phishing")
    print("=" * 70)

    if len(false_positives) > 0:

        print(
            "\nPhishing probability statistics:"
        )

        print(
            f"Mean   : {fp_probability.mean():.6f}"
        )

        print(
            f"Median : {fp_probability.median():.6f}"
        )

        print(
            f"Minimum: {fp_probability.min():.6f}"
        )

        print(
            f"Maximum: {fp_probability.max():.6f}"
        )

        print("\nSample false positives:")

        print(
            false_positives[
                [
                    "URL",
                    "phishing_probability"
                ]
            ]
            .sort_values(
                "phishing_probability",
                ascending=False
            )
            .head(30)
            .to_string(index=False)
        )

    # ---------------------------------------------------------
    # Common URL characteristics
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ERROR GROUP FEATURE SUMMARY")
    print("=" * 70)

    feature_columns = [
        "URLLength",
        "DomainLength",
        "NoOfSubDomain",
        "NoOfLettersInURL",
        "NoOfDegitsInURL",
        "NoOfOtherSpecialCharsInURL",
        "IsHTTPS",
        "path_length",
        "query_length",
        "num_dots",
        "has_at_symbol",
        "has_hyphen_in_domain",
        "suspicious_keyword_count",
        "IsWWWSubdomain",
    ]

    available_features = [
        col
        for col in feature_columns
        if col in features_df.columns
    ]

    # Add feature values to result table
    for col in available_features:
        results[col] = features_df[col].values

    fn_with_features = results[
        (results["label"] == 0)
        &
        (results["predicted_label"] == 1)
    ]

    fp_with_features = results[
        (results["label"] == 1)
        &
        (results["predicted_label"] == 0)
    ]

    if len(fn_with_features) > 0:

        print("\nFalse Negative feature means:")

        print(
            fn_with_features[
                available_features
            ].mean(numeric_only=True)
            .round(4)
            .to_string()
        )

    if len(fp_with_features) > 0:

        print("\nFalse Positive feature means:")

        print(
            fp_with_features[
                available_features
            ].mean(numeric_only=True)
            .round(4)
            .to_string()
        )

    # ---------------------------------------------------------
    # Save complete error analysis
    # ---------------------------------------------------------

    complete_file = (
        OUTPUT_DIR
        / "all_predictions.csv"
    )

    results.to_csv(
        complete_file,
        index=False
    )

    print("\n" + "=" * 70)
    print("FILES SAVED")
    print("=" * 70)

    print(f"\nFalse negatives:")
    print(fn_file)

    print(f"\nFalse positives:")
    print(fp_file)

    print(f"\nAll predictions:")
    print(complete_file)

    print("\n" + "=" * 70)
    print("ERROR ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()