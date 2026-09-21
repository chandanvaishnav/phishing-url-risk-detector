from pathlib import Path

import joblib
import pandas as pd

from app.features.url_features import extract_url_features

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_url_adapted.joblib"
)

ADAPTATION_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation.csv"
)


def main():

    print("Loading 25-feature adapted model...")
    model = joblib.load(MODEL_FILE)

    print("Loading URL-Phish adaptation dataset...")
    df = pd.read_csv(ADAPTATION_FILE)

    print(f"Adaptation URLs: {len(df):,}")
    print()

    # --------------------------------------------------------
    # Extract URL features
    # --------------------------------------------------------

    print("Extracting URL features...")

    feature_rows = df["URL"].apply(
        extract_url_features
    )

    X = pd.DataFrame(
        feature_rows.tolist()
    )

    # Match exact feature order used by model
    if hasattr(model, "feature_names_in_"):
        X = X[list(model.feature_names_in_)]

    print(
        f"Features used: {X.shape[1]}"
    )

    # --------------------------------------------------------
    # Get model probabilities
    # --------------------------------------------------------

    print("Calculating phishing probabilities...")

    probabilities = model.predict_proba(X)

    # Model convention:
    # 0 = phishing
    # 1 = legitimate

    phishing_probability = probabilities[:, 0]

    actual = (
        df["label"]
        .astype(int)
        .values
    )

    # --------------------------------------------------------
    # Threshold analysis
    # --------------------------------------------------------

    thresholds = [
        0.10,
        0.15,
        0.20,
        0.25,
        0.30,
        0.35,
        0.40,
        0.45,
        0.50,
        0.55,
        0.60,
        0.65,
        0.70,
        0.75,
        0.80,
        0.85,
        0.90,
        0.95,
    ]

    results = []

    print()
    print("=" * 95)
    print("THRESHOLD TUNING — VALIDATION DATA")
    print("=" * 95)

    print(
        f"{'Threshold':>10}"
        f"{'Accuracy':>12}"
        f"{'Precision':>12}"
        f"{'Recall':>12}"
        f"{'F1':>12}"
        f"{'FP':>10}"
        f"{'FN':>10}"
    )

    print("-" * 95)

    for threshold in thresholds:

        # phishing_probability >= threshold
        # → phishing = 0
        #
        # phishing_probability < threshold
        # → legitimate = 1

        predictions = (
            phishing_probability < threshold
        ).astype(int)

        accuracy = accuracy_score(
            actual,
            predictions
        )

        precision = precision_score(
            actual,
            predictions,
            pos_label=0,
            zero_division=0
        )

        recall = recall_score(
            actual,
            predictions,
            pos_label=0,
            zero_division=0
        )

        f1 = f1_score(
            actual,
            predictions,
            pos_label=0,
            zero_division=0
        )

        # Confusion matrix manually
        phishing_actual = actual == 0
        legitimate_actual = actual == 1

        phishing_predicted = predictions == 0
        legitimate_predicted = predictions == 1

        true_positive = int(
            (phishing_actual & phishing_predicted).sum()
        )

        false_negative = int(
            (phishing_actual & legitimate_predicted).sum()
        )

        false_positive = int(
            (legitimate_actual & phishing_predicted).sum()
        )

        results.append({
            "threshold": threshold,
            "accuracy": accuracy,
            "phishing_precision": precision,
            "phishing_recall": recall,
            "phishing_f1": f1,
            "false_positives": false_positive,
            "false_negatives": false_negative,
        })

        print(
            f"{threshold:>10.2f}"
            f"{accuracy:>12.4f}"
            f"{precision:>12.4f}"
            f"{recall:>12.4f}"
            f"{f1:>12.4f}"
            f"{false_positive:>10}"
            f"{false_negative:>10}"
        )

    # --------------------------------------------------------
    # Find best threshold by F1
    # --------------------------------------------------------

    results_df = pd.DataFrame(results)

    best = results_df.loc[
        results_df["phishing_f1"].idxmax()
    ]

    print()
    print("=" * 95)
    print("BEST VALIDATION THRESHOLD BY PHISHING F1")
    print("=" * 95)

    print(
        f"Threshold:          {best['threshold']:.2f}"
    )

    print(
        f"Accuracy:            {best['accuracy']:.6f}"
    )

    print(
        f"Phishing Precision:  "
        f"{best['phishing_precision']:.6f}"
    )

    print(
        f"Phishing Recall:     "
        f"{best['phishing_recall']:.6f}"
    )

    print(
        f"Phishing F1:         "
        f"{best['phishing_f1']:.6f}"
    )

    print(
        f"False Positives:     "
        f"{int(best['false_positives'])}"
    )

    print(
        f"False Negatives:     "
        f"{int(best['false_negatives'])}"
    )

    # --------------------------------------------------------
    # Save threshold results
    # --------------------------------------------------------

    output_file = (
        PROJECT_ROOT
        / "data"
        / "processed"
        / "validation_threshold_analysis.csv"
    )

    results_df.to_csv(
        output_file,
        index=False
    )

    print()
    print(
        f"Results saved to: {output_file}"
    )

    print()
    print("Validation threshold tuning complete.")


if __name__ == "__main__":
    main()