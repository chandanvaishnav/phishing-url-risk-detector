from pathlib import Path

import joblib
import pandas as pd

from app.features.url_features import extract_url_features
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_adapted_23features.joblib"
)

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_external_test.csv"
)


# ============================================================
# FEATURES REMOVED FROM THE 23-FEATURE MODEL
# ============================================================

REMOVE_FEATURES = [
    "IsHTTPS",
    "IsWWWSubdomain",
]


# ============================================================
# MAIN
# ============================================================

def main():

    print("Loading 23-feature adapted model...")
    model = joblib.load(MODEL_FILE)

    print(f"Model loaded: {MODEL_FILE}")
    print()

    print("Loading external URL-Phish test dataset...")
    df = pd.read_csv(TEST_FILE)

    print(f"External test URLs: {len(df):,}")
    print()

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    if "URL" not in df.columns:
        raise ValueError(
            f"Expected 'URL' column not found. "
            f"Available columns: {list(df.columns)}"
        )

    if "label" not in df.columns:
        raise ValueError(
            f"Expected 'label' column not found. "
            f"Available columns: {list(df.columns)}"
        )

    # --------------------------------------------------------
    # Extract URL features
    # --------------------------------------------------------

    print("Extracting URL features...")

    feature_rows = df["URL"].apply(extract_url_features)

    features_df = pd.DataFrame(feature_rows.tolist())

    # Remove the two features not used by the 23-feature model
    features_df = features_df.drop(
        columns=REMOVE_FEATURES,
        errors="ignore"
    )

    print(f"Features used for prediction: {features_df.shape[1]}")
    print()

    # --------------------------------------------------------
    # Match model feature order
    # --------------------------------------------------------

    if hasattr(model, "feature_names_in_"):

        expected_features = list(model.feature_names_in_)
        actual_features = list(features_df.columns)

        missing = [
            feature
            for feature in expected_features
            if feature not in actual_features
        ]

        extra = [
            feature
            for feature in actual_features
            if feature not in expected_features
        ]

        if missing:
            print("Missing model features:")
            print(missing)
            raise ValueError(
                "Required model features are missing."
            )

        if actual_features != expected_features:
            print("Feature order differs from model.")
            print("Correcting feature order...")

            features_df = features_df[expected_features]

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    print("Running predictions...")

    X = features_df

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    # Model convention:
    # 0 = phishing
    # 1 = legitimate

    phishing_probability = probabilities[:, 0]

    actual_labels = df["label"].astype(int).values

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        actual_labels,
        predictions
    )

    phishing_precision = precision_score(
        actual_labels,
        predictions,
        pos_label=0,
        zero_division=0
    )

    phishing_recall = recall_score(
        actual_labels,
        predictions,
        pos_label=0,
        zero_division=0
    )

    phishing_f1 = f1_score(
        actual_labels,
        predictions,
        pos_label=0,
        zero_division=0
    )

    cm = confusion_matrix(
        actual_labels,
        predictions,
        labels=[0, 1]
    )

    correct = int(
        (predictions == actual_labels).sum()
    )

    wrong = int(
        (predictions != actual_labels).sum()
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("23-FEATURE ADAPTED MODEL — EXTERNAL TEST")
    print("=" * 60)

    print(f"Accuracy:              {accuracy:.6f}")
    print(f"Phishing Precision:    {phishing_precision:.6f}")
    print(f"Phishing Recall:       {phishing_recall:.6f}")
    print(f"Phishing F1:           {phishing_f1:.6f}")

    print()
    print("Confusion Matrix")
    print("(rows = actual, columns = predicted)")
    print()

    print("                 Predicted")
    print("              Phishing  Legitimate")

    print(
        f"Actual Phishing   {cm[0, 0]:6d}    {cm[0, 1]:6d}"
    )

    print(
        f"Actual Legitimate {cm[1, 0]:6d}    {cm[1, 1]:6d}"
    )

    print()
    print(f"Correct predictions: {correct:,}")
    print(f"Wrong predictions:   {wrong:,}")

    # --------------------------------------------------------
    # Probability statistics
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("PHISHING PROBABILITY STATISTICS")
    print("=" * 60)

    phishing_mask = actual_labels == 0
    legitimate_mask = actual_labels == 1

    print(
        f"Actual phishing mean probability: "
        f"{phishing_probability[phishing_mask].mean():.6f}"
    )

    print(
        f"Actual legitimate mean probability: "
        f"{phishing_probability[legitimate_mask].mean():.6f}"
    )

    print()
    print("Evaluation complete.")


if __name__ == "__main__":
    main()