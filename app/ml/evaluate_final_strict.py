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

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_strict_external_test.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "final_strict_evaluation.csv"
)

# LOCKED BEFORE LOOKING AT THE STRICT TEST
THRESHOLD = 0.95


def main():

    print("=" * 70)
    print("FINAL STRICT EXTERNAL EVALUATION")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load final model
    # ---------------------------------------------------------

    print("\nLoading final model...")

    model = joblib.load(MODEL_FILE)

    print("Model loaded successfully.")

    # ---------------------------------------------------------
    # Load untouched strict external test
    # ---------------------------------------------------------

    print("\nLoading strict external test...")

    df = pd.read_csv(TEST_FILE)

    print(f"Test URLs: {len(df):,}")

    # ---------------------------------------------------------
    # Extract features
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
    # Verify feature compatibility
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
    # Prediction probabilities
    #
    # Class 0 = phishing
    # Class 1 = legitimate
    # ---------------------------------------------------------

    print("\nCalculating predictions...")

    probabilities = model.predict_proba(X)

    phishing_index = list(
        model.classes_
    ).index(0)

    phishing_probability = probabilities[
        :, phishing_index
    ]

    # ---------------------------------------------------------
    # Apply LOCKED threshold
    #
    # phishing probability >= 0.95
    #       -> phishing (0)
    #
    # phishing probability < 0.95
    #       -> legitimate (1)
    # ---------------------------------------------------------

    y_pred = (
        phishing_probability < THRESHOLD
    ).astype(int)

    # ---------------------------------------------------------
    # Metrics
    # ---------------------------------------------------------

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

    # Matrix:
    #
    #                 Predicted
    #                 Phishing  Legitimate
    # Actual Phishing    TP        FN
    #        Legitimate  FP        TN
    #

    tp = cm[0, 0]
    fn = cm[0, 1]
    fp = cm[1, 0]
    tn = cm[1, 1]

    # ---------------------------------------------------------
    # Additional probability analysis
    # ---------------------------------------------------------

    phishing_probs_actual_phishing = (
        phishing_probability[y_true == 0]
    )

    phishing_probs_actual_legitimate = (
        phishing_probability[y_true == 1]
    )

    # ---------------------------------------------------------
    # Print final results
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)

    print(f"\nLocked threshold: {THRESHOLD:.2f}")

    print(f"\nAccuracy           : {accuracy:.4f}")
    print(f"Accuracy (%)       : {accuracy * 100:.2f}%")

    print(
        f"\nPhishing Precision : "
        f"{precision:.4f}"
    )

    print(
        f"Phishing Precision (%): "
        f"{precision * 100:.2f}%"
    )

    print(
        f"\nPhishing Recall    : "
        f"{recall:.4f}"
    )

    print(
        f"Phishing Recall (%): "
        f"{recall * 100:.2f}%"
    )

    print(
        f"\nPhishing F1        : "
        f"{f1:.4f}"
    )

    print(
        f"Phishing F1 (%): "
        f"{f1 * 100:.2f}%"
    )

    print("\nConfusion Matrix:")
    print(cm)

    print("\nDetailed counts:")
    print(f"True Positives  (Phishing correctly detected): {tp}")
    print(f"False Negatives (Phishing missed):             {fn}")
    print(f"False Positives (Legitimate flagged):          {fp}")
    print(f"True Negatives  (Legitimate correctly detected):{tn}")

    print(
        "\nMean phishing probability "
        "for actual phishing URLs:"
    )

    print(
        f"{phishing_probs_actual_phishing.mean():.6f}"
    )

    print(
        "\nMean phishing probability "
        "for actual legitimate URLs:"
    )

    print(
        f"{phishing_probs_actual_legitimate.mean():.6f}"
    )

    # ---------------------------------------------------------
    # Save one-row summary
    # ---------------------------------------------------------

    summary = pd.DataFrame([{
        "model": "random_forest_url_final",
        "threshold": THRESHOLD,
        "test_urls": len(df),
        "accuracy": accuracy,
        "phishing_precision": precision,
        "phishing_recall": recall,
        "phishing_f1": f1,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "mean_phishing_probability_actual_phishing":
            phishing_probs_actual_phishing.mean(),
        "mean_phishing_probability_actual_legitimate":
            phishing_probs_actual_legitimate.mean()
    }])

    summary.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\nResults saved to:")
    print(OUTPUT_FILE)

    print("\n" + "=" * 70)
    print("FINAL STRICT EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()