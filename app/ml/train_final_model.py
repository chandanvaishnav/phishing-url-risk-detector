from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]

BASE_FEATURES = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phiusiiL_plus_tranco_features.csv"
)

ADAPTATION_FEATURES = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_features.csv"
)

VALIDATION_FEATURES = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_validation.csv"
)

OUTPUT_MODEL = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_final.joblib"
)


def main():

    print("=" * 70)
    print("TRAINING FINAL PHISHING URL MODEL")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load base feature dataset
    # ---------------------------------------------------------

    print("\nLoading base features...")

    base = pd.read_csv(BASE_FEATURES)

    print(f"Base rows: {len(base):,}")

    # ---------------------------------------------------------
    # Load adaptation TRAIN feature dataset
    # ---------------------------------------------------------

    print("\nLoading adaptation features...")

    adaptation = pd.read_csv(ADAPTATION_FEATURES)

    # We need only rows belonging to the new adaptation TRAIN split.
    validation_urls = set(
        pd.read_csv(VALIDATION_FEATURES, usecols=["URL"])["URL"]
    )

    # The feature file does not contain URL, so the safest way
    # is to rebuild features for the adaptation TRAIN URLs.
    #
    # Therefore this script uses the original adaptation CSV
    # and extracts the required feature rows.
    # ---------------------------------------------------------

    adaptation_urls_file = (
        PROJECT_ROOT
        / "data"
        / "external"
        / "urlphish_adaptation_train.csv"
    )

    adaptation_train_urls = pd.read_csv(adaptation_urls_file)

    print(
        f"Adaptation training rows: "
        f"{len(adaptation_train_urls):,}"
    )

    # ---------------------------------------------------------
    # Match adaptation feature rows to training URLs
    # ---------------------------------------------------------

    from app.features.url_features import extract_url_features

    print("\nExtracting features for adaptation training URLs...")

    feature_rows = adaptation_train_urls["URL"].apply(
        extract_url_features
    )

    adaptation_train_features = pd.DataFrame(
        feature_rows.tolist()
    )

    adaptation_train_features["label"] = (
        adaptation_train_urls["label"].values
    )

    print(
        "Adaptation feature shape:",
        adaptation_train_features.shape
    )

    # ---------------------------------------------------------
    # Verify feature columns
    # ---------------------------------------------------------

    base_feature_columns = [
        col for col in base.columns
        if col != "label"
    ]

    adaptation_feature_columns = [
        col for col in adaptation_train_features.columns
        if col != "label"
    ]

    if base_feature_columns != adaptation_feature_columns:

        raise ValueError(
            "Feature columns do not match!\n"
            f"Base: {base_feature_columns}\n"
            f"Adaptation: {adaptation_feature_columns}"
        )

    # ---------------------------------------------------------
    # Remove HTTPS and WWW?
    #
    # NO.
    #
    # We already tested both 23 and 25 features.
    # The 25-feature model performed better on the strict test.
    # ---------------------------------------------------------

    X_base = base[base_feature_columns]
    y_base = base["label"]

    X_adaptation = adaptation_train_features[
        adaptation_feature_columns
    ]
    y_adaptation = adaptation_train_features["label"]

    # ---------------------------------------------------------
    # Combine training data
    # ---------------------------------------------------------

    X = pd.concat(
        [X_base, X_adaptation],
        ignore_index=True
    )

    y = pd.concat(
        [y_base, y_adaptation],
        ignore_index=True
    )

    print("\nCombined training dataset:")
    print(f"Rows: {len(X):,}")
    print(f"Features: {len(X.columns)}")

    print("\nLabel distribution:")
    print(y.value_counts().to_dict())

    # ---------------------------------------------------------
    # Train final Random Forest
    # ---------------------------------------------------------

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=400,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
        max_features="sqrt"
    )

    model.fit(X, y)

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    OUTPUT_MODEL.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(model, OUTPUT_MODEL)

    print("\nModel saved:")
    print(OUTPUT_MODEL)

    # ---------------------------------------------------------
    # Feature importance
    # ---------------------------------------------------------

    importance = pd.DataFrame({
        "feature": X.columns,
        "importance": model.feature_importances_
    }).sort_values(
        "importance",
        ascending=False
    )

    print("\nTop 10 feature importance:")

    print(
        importance.head(10).to_string(index=False)
    )

    print("\n" + "=" * 70)
    print("FINAL MODEL TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()