from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]

BASE_FEATURES_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phiusiiL_plus_tranco_features.csv"
)

ADAPTATION_FEATURES_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_features.csv"
)

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_adapted_23features.joblib"
)

RANDOM_STATE = 42

REMOVE_FEATURES = [
    "IsHTTPS",
    "IsWWWSubdomain",
]


def main():

    print("Loading base PhiUSIIL + Tranco features...")
    base = pd.read_csv(BASE_FEATURES_FILE)

    print(f"Base dataset: {len(base):,} URLs")

    print()
    print("Loading URL-Phish adaptation features...")
    adaptation = pd.read_csv(ADAPTATION_FEATURES_FILE)

    print(f"Adaptation dataset: {len(adaptation):,} URLs")

    # Verify compatibility before removing features
    if list(base.columns) != list(adaptation.columns):
        raise ValueError(
            "Feature columns do not match between datasets."
        )

    print()
    print("Feature compatibility: OK")

    # Remove HTTPS and WWW features
    base = base.drop(columns=REMOVE_FEATURES)
    adaptation = adaptation.drop(columns=REMOVE_FEATURES)

    # Combine without dropping duplicate feature vectors
    combined = pd.concat(
        [base, adaptation],
        ignore_index=True
    )

    print()
    print("========== COMBINED TRAINING DATA ==========")
    print(f"Total URLs: {len(combined):,}")
    print(
        "Expected URLs:",
        len(base) + len(adaptation)
    )

    print()
    print("Removed features:")
    print(REMOVE_FEATURES)

    print()
    print("Remaining ML features:")
    print(len(combined.columns) - 1)

    print()
    print("Label distribution:")
    print(
        combined["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    # Prepare ML data
    X = combined.drop(columns=["label"])
    y = combined["label"]

    print()
    print("Training 23-feature Random Forest...")

    model = RandomForestClassifier(
        n_estimators=400,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced_subsample",
        max_features="sqrt",
    )

    model.fit(X, y)

    print("Training complete.")

    # Save model
    joblib.dump(model, MODEL_FILE)

    print()
    print(f"Model saved to: {MODEL_FILE}")

    print()
    print("========== FEATURE IMPORTANCE ==========")

    importance = (
        pd.Series(
            model.feature_importances_,
            index=X.columns
        )
        .sort_values(ascending=False)
    )

    print(importance.to_string())


if __name__ == "__main__":
    main()