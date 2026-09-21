import pandas as pd

from app.features.url_features import extract_url_features


TRAINING_FILE = "data/processed/url_features.csv"
EXTERNAL_FILE = "data/external/legitimate_validation.csv"


def main():
    print("\n" + "=" * 75)
    print("TRAINING vs EXTERNAL FEATURE DIAGNOSTIC")
    print("=" * 75)

    # Load data
    training = pd.read_csv(TRAINING_FILE)
    external_urls = pd.read_csv(EXTERNAL_FILE)

    # URL-only feature columns
    feature_columns = [
        column
        for column in training.columns
        if column != "label"
    ]

    # Extract external features
    external_features = pd.DataFrame(
        external_urls["URL"]
        .apply(extract_url_features)
        .tolist()
    )

    external_features = external_features[
        feature_columns
    ]

    print("\nTraining dataset:")
    print(f"Rows: {len(training)}")

    print("\nExternal validation:")
    print(f"Rows: {len(external_features)}")

    # --------------------------------------------------
    # Compare statistics
    # --------------------------------------------------

    print("\n" + "=" * 75)
    print("FEATURE DISTRIBUTION COMPARISON")
    print("=" * 75)

    rows = []

    for feature in feature_columns:
        train_mean = training[
            feature
        ].mean()

        external_mean = external_features[
            feature
        ].mean()

        train_median = training[
            feature
        ].median()

        external_median = external_features[
            feature
        ].median()

        rows.append(
            {
                "feature": feature,
                "training_mean": train_mean,
                "external_mean": external_mean,
                "training_median": train_median,
                "external_median": external_median,
            }
        )

    comparison = pd.DataFrame(rows)

    comparison[
        "mean_difference"
    ] = (
        comparison["external_mean"]
        - comparison["training_mean"]
    ).abs()

    comparison = comparison.sort_values(
        "mean_difference",
        ascending=False,
    )

    pd.set_option(
        "display.max_rows",
        100,
    )

    pd.set_option(
        "display.float_format",
        lambda value: f"{value:.4f}",
    )

    print(
        comparison.to_string(
            index=False
        )
    )

    # --------------------------------------------------
    # External feature values
    # --------------------------------------------------

    print("\n" + "=" * 75)
    print("EXTERNAL URL FEATURE VALUES")
    print("=" * 75)

    external_display = external_features.copy()

    external_display.insert(
        0,
        "URL",
        external_urls["URL"].values,
    )

    print(
        external_display.to_string(
            index=False
        )
    )

    # Save results
    output_file = (
        "data/processed/"
        "external_feature_comparison.csv"
    )

    comparison.to_csv(
        output_file,
        index=False,
    )

    print(
        f"\nComparison saved to: {output_file}"
    )


if __name__ == "__main__":
    main()