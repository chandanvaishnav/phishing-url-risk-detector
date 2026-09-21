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

    print("Loading strict external test dataset...")
    df = pd.read_csv(TEST_FILE)

    print(f"Test URLs: {len(df):,}")
    print()

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    print("Extracting URL features...")

    feature_rows = df["URL"].apply(
        extract_url_features
    )

    X = pd.DataFrame(
        feature_rows.tolist()
    )

    # Match model feature order
    if hasattr(model, "feature_names_in_"):
        X = X[list(model.feature_names_in_)]

    print(
        f"Features used: {X.shape[1]}"
    )

    # --------------------------------------------------------
    # Get phishing probabilities
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
    # Thresholds
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
    print("THRESHOLD ANALYSIS — STRICT EXTERNAL TEST")
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

        # Phishing probability >= threshold
        # means prediction = phishing (label 0).
        #
        # Otherwise prediction = legitimate (label 1).

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

        cm = confusion_matrix(
            actual,
            predictions,
            labels=[0, 1]
        )

        # Actual legitimate predicted phishing
        fp = int(cm[1, 0])

        # Actual phishing predicted legitimate
        fn = int(cm[0, 1])

        results.append({
            "threshold": threshold,
            "accuracy": accuracy,
            "phishing_precision": precision,
            "phishing_recall": recall,
            "phishing_f1": f1,
            "false_positives": fp,
            "false_negatives": fn,
        })

        print(
            f"{threshold:>10.2f}"
            f"{accuracy:>12.4f}"
            f"{precision:>12.4f}"
            f"{recall:>12.4f}"
            f"{f1:>12.4f}"
            f"{fp:>10}"
            f"{fn:>10}"
        )

    # --------------------------------------------------------
    # Best F1 threshold
    # --------------------------------------------------------

    results_df = pd.DataFrame(results)

    best = results_df.loc[
        results_df["phishing_f1"].idxmax()
    ]

    print()
    print("=" * 95)
    print("BEST THRESHOLD BY PHISHING F1")
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
    # Save results
    # --------------------------------------------------------

    output_file = (
        PROJECT_ROOT
        / "data"
        / "processed"
        / "strict_threshold_analysis.csv"
    )

    results_df.to_csv(
        output_file,
        index=False
    )

    print()
    print(
        f"Results saved to: {output_file}"
    )


if __name__ == "__main__":
    main()