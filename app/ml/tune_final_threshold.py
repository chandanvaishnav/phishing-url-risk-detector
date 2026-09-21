from pathlib import Path

import joblib
import pandas as pd
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
    / "random_forest_url_final.joblib"
)

VALIDATION_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_validation.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "final_threshold_analysis.csv"
)


def main():

    print("=" * 70)
    print("FINAL MODEL — VALIDATION THRESHOLD ANALYSIS")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load model
    # ---------------------------------------------------------

    print("\nLoading final model...")
    model = joblib.load(MODEL_FILE)

    print("Model loaded successfully.")

    # ---------------------------------------------------------
    # Load validation data
    # ---------------------------------------------------------

    print("\nLoading validation dataset...")

    df = pd.read_csv(VALIDATION_FILE)

    print(f"Validation URLs: {len(df):,}")

    # ---------------------------------------------------------
    # Feature extraction
    # ---------------------------------------------------------

    from app.features.url_features import extract_url_features

    print("\nExtracting URL features...")

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

    print(f"Features: {X.shape[1]}")

    # ---------------------------------------------------------
    # Verify model/features
    # ---------------------------------------------------------

    if hasattr(model, "feature_names_in_"):

        model_features = list(
            model.feature_names_in_
        )

        current_features = list(X.columns)

        if model_features != current_features:

            raise ValueError(
                "Feature mismatch!\n\n"
                f"Model features:\n{model_features}\n\n"
                f"Current features:\n{current_features}"
            )

    # ---------------------------------------------------------
    # Get probabilities
    #
    # Class 0 = phishing
    # Class 1 = legitimate
    # ---------------------------------------------------------

    print("\nCalculating phishing probabilities...")

    probabilities = model.predict_proba(X)

    phishing_index = list(
        model.classes_
    ).index(0)

    phishing_probability = probabilities[
        :, phishing_index
    ]

    # ---------------------------------------------------------
    # Threshold testing
    # ---------------------------------------------------------

    thresholds = [
        round(x / 100, 2)
        for x in range(10, 100, 5)
    ]

    results = []

    print("\n")
    print(
        f"{'Threshold':>10} "
        f"{'Accuracy':>10} "
        f"{'Precision':>12} "
        f"{'Recall':>10} "
        f"{'F1':>10} "
        f"{'FP':>8} "
        f"{'FN':>8}"
    )

    print("-" * 75)

    for threshold in thresholds:

        # Phishing = 0
        # Legitimate = 1

        y_pred = (
            phishing_probability < threshold
        ).astype(int)

        accuracy = accuracy_score(
            y_true,
            y_pred
        )

        precision = precision_score(
            y_true,
            y_pred,
            pos_label=0,
            zero_division=0
        )

        recall = recall_score(
            y_true,
            y_pred,
            pos_label=0,
            zero_division=0
        )

        f1 = f1_score(
            y_true,
            y_pred,
            pos_label=0,
            zero_division=0
        )

        cm = confusion_matrix(
            y_true,
            y_pred,
            labels=[0, 1]
        )

        # Confusion matrix:
        #
        #             Predicted
        #             Phish  Legit
        # Actual Phish   TP     FN
        #        Legit   FP     TN
        #

        tp = cm[0, 0]
        fn = cm[0, 1]
        fp = cm[1, 0]
        tn = cm[1, 1]

        results.append({
            "threshold": threshold,
            "accuracy": accuracy,
            "phishing_precision": precision,
            "phishing_recall": recall,
            "phishing_f1": f1,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "true_negatives": tn
        })

        print(
            f"{threshold:10.2f} "
            f"{accuracy:10.4f} "
            f"{precision:12.4f} "
            f"{recall:10.4f} "
            f"{f1:10.4f} "
            f"{fp:8d} "
            f"{fn:8d}"
        )

    # ---------------------------------------------------------
    # Find best threshold by phishing F1
    # ---------------------------------------------------------

    results_df = pd.DataFrame(results)

    best_row = results_df.loc[
        results_df["phishing_f1"].idxmax()
    ]

    best_threshold = best_row["threshold"]

    # ---------------------------------------------------------
    # Save results
    # ---------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    results_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("BEST VALIDATION THRESHOLD")
    print("=" * 70)

    print(
        f"Threshold          : {best_threshold:.2f}"
    )

    print(
        f"Accuracy            : "
        f"{best_row['accuracy']:.4f}"
    )

    print(
        f"Phishing Precision  : "
        f"{best_row['phishing_precision']:.4f}"
    )

    print(
        f"Phishing Recall     : "
        f"{best_row['phishing_recall']:.4f}"
    )

    print(
        f"Phishing F1         : "
        f"{best_row['phishing_f1']:.4f}"
    )

    print(
        f"False Positives     : "
        f"{int(best_row['false_positives'])}"
    )

    print(
        f"False Negatives     : "
        f"{int(best_row['false_negatives'])}"
    )

    print("\nResults saved:")
    print(OUTPUT_FILE)

    print("=" * 70)


if __name__ == "__main__":
    main()