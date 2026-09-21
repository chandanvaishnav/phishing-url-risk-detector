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


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_adapted.joblib"
)

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_strict_external_test.csv"
)


def main():

    print("Loading 25-feature adapted model...")
    model = joblib.load(MODEL_FILE)

    print(f"Model loaded: {MODEL_FILE}")
    print()

    print("Loading strict external test dataset...")
    df = pd.read_csv(TEST_FILE)

    print(f"Strict external test URLs: {len(df):,}")
    print()

    # --------------------------------------------------------
    # Check columns
    # --------------------------------------------------------

    if "URL" not in df.columns:
        raise ValueError(
            f"'URL' column not found. "
            f"Available columns: {list(df.columns)}"
        )

    if "label" not in df.columns:
        raise ValueError(
            f"'label' column not found. "
            f"Available columns: {list(df.columns)}"
        )

    # --------------------------------------------------------
    # Feature extraction
    # --------------------------------------------------------

    print("Extracting URL features...")

    feature_rows = df["URL"].apply(
        extract_url_features
    )

    features_df = pd.DataFrame(
        feature_rows.tolist()
    )

    print(
        f"Features extracted: "
        f"{features_df.shape[1]}"
    )

    # --------------------------------------------------------
    # Match model feature order
    # --------------------------------------------------------

    if hasattr(model, "feature_names_in_"):

        expected_features = list(
            model.feature_names_in_
        )

        actual_features = list(
            features_df.columns
        )

        missing = [
            feature
            for feature in expected_features
            if feature not in actual_features
        ]

        if missing:
            raise ValueError(
                f"Missing model features: {missing}"
            )

        if actual_features != expected_features:

            print(
                "Feature order differs from model."
            )

            features_df = features_df[
                expected_features
            ]

            print(
                "Feature order corrected."
            )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    print()
    print("Running predictions...")

    predictions = model.predict(
        features_df
    )

    probabilities = model.predict_proba(
        features_df
    )

    # Model convention:
    # 0 = phishing
    # 1 = legitimate

    phishing_probability = probabilities[:, 0]

    actual_labels = (
        df["label"]
        .astype(int)
        .values
    )

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
    print("25-FEATURE ADAPTED MODEL — STRICT EXTERNAL TEST")
    print("=" * 60)

    print(
        f"Accuracy:              {accuracy:.6f}"
    )

    print(
        f"Phishing Precision:    {phishing_precision:.6f}"
    )

    print(
        f"Phishing Recall:       {phishing_recall:.6f}"
    )

    print(
        f"Phishing F1:           {phishing_f1:.6f}"
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print()
    print("Confusion Matrix")
    print("(rows = actual, columns = predicted)")
    print()

    print("                 Predicted")
    print("              Phishing  Legitimate")

    print(
        f"Actual Phishing   "
        f"{cm[0, 0]:6d}    "
        f"{cm[0, 1]:6d}"
    )

    print(
        f"Actual Legitimate "
        f"{cm[1, 0]:6d}    "
        f"{cm[1, 1]:6d}"
    )

    print()
    print(
        f"Correct predictions: {correct:,}"
    )

    print(
        f"Wrong predictions:   {wrong:,}"
    )

    # --------------------------------------------------------
    # Probability statistics
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("PHISHING PROBABILITY STATISTICS")
    print("=" * 60)

    phishing_mask = (
        actual_labels == 0
    )

    legitimate_mask = (
        actual_labels == 1
    )

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
    