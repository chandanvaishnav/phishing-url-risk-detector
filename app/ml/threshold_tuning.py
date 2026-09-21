import pandas as pd
import tldextract
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


MODEL_FILE = (
    "models/random_forest_url_all_features.joblib"
)

FEATURE_FILE = (
    "data/processed/url_features.csv"
)

DATA_FILE = (
    "data/processed/phiusiiL_cleaned.csv"
)

OUTPUT_FILE = (
    "data/processed/threshold_results.csv"
)

RANDOM_STATE = 42
TEST_SIZE = 0.20


def get_registered_domain(url):
    """
    Return the registrable domain using the
    Public Suffix List.
    """

    extracted = tldextract.extract(
        str(url)
    )

    registered_domain = (
        extracted.top_domain_under_public_suffix
    )

    if registered_domain:
        return registered_domain.lower()

    hostname = extracted.fqdn

    return hostname.lower()


def main():

    print("=" * 70)
    print("PHISHING THRESHOLD TUNING")
    print("=" * 70)

    # --------------------------------------------------
    # Load model
    # --------------------------------------------------

    print("\nLoading model...")

    model = joblib.load(
        MODEL_FILE
    )

    print(
        "Model loaded successfully."
    )

    # --------------------------------------------------
    # Load features
    # --------------------------------------------------

    print(
        "\nLoading feature dataset..."
    )

    features_df = pd.read_csv(
        FEATURE_FILE
    )

    print(
        f"Feature dataset size: "
        f"{len(features_df)}"
    )

    # --------------------------------------------------
    # Load URLs and labels
    # --------------------------------------------------

    print(
        "\nLoading original dataset..."
    )

    original_df = pd.read_csv(
        DATA_FILE,
        usecols=[
            "URL",
            "label",
        ],
    )

    if len(original_df) != len(
        features_df
    ):
        raise ValueError(
            "Feature dataset and original "
            "dataset have different row counts."
        )

    # --------------------------------------------------
    # Create registered-domain groups
    # --------------------------------------------------

    print(
        "\nCreating registered-domain groups..."
    )

    groups = original_df[
        "URL"
    ].apply(
        get_registered_domain
    )

    print(
        f"Unique registered domains: "
        f"{groups.nunique()}"
    )

    # --------------------------------------------------
    # Prepare complete feature matrix
    # --------------------------------------------------

    feature_columns = (
        model.feature_names_in_
    )

    X_all = features_df[
        feature_columns
    ]

    y_all = features_df[
        "label"
    ]

    # --------------------------------------------------
    # EXACT SAME SPLIT AS train_compare_models.py
    # --------------------------------------------------

    print(
        "\nCreating exact unseen-domain split..."
    )

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )

    train_idx, test_idx = next(
        splitter.split(
            X_all,
            y_all,
            groups,
        )
    )

    train_domains = set(
        groups.iloc[train_idx]
    )

    test_domains = set(
        groups.iloc[test_idx]
    )

    overlap = (
        train_domains
        .intersection(
            test_domains
        )
    )

    print(
        f"Training samples: "
        f"{len(train_idx)}"
    )

    print(
        f"Testing samples: "
        f"{len(test_idx)}"
    )

    print(
        f"Training domains: "
        f"{len(train_domains)}"
    )

    print(
        f"Testing domains: "
        f"{len(test_domains)}"
    )

    print(
        f"Domain overlap: "
        f"{len(overlap)}"
    )

    if overlap:
        raise RuntimeError(
            "Registered-domain leakage detected."
        )

    # --------------------------------------------------
    # Test set
    # --------------------------------------------------

    X_test = X_all.iloc[
        test_idx
    ]

    y_test = y_all.iloc[
        test_idx
    ]

    print(
        "\nTest feature shape:"
    )

    print(
        X_test.shape
    )

    # --------------------------------------------------
    # Predict probabilities
    # --------------------------------------------------

    print(
        "\nCalculating phishing probabilities..."
    )

    probabilities = model.predict_proba(
        X_test
    )

    class_to_index = {
        int(label): index
        for index, label
        in enumerate(model.classes_)
    }

    phishing_index = class_to_index[
        0
    ]

    phishing_probability = (
        probabilities[
            :,
            phishing_index,
        ]
    )

    print(
        "Probability calculation completed."
    )

    # --------------------------------------------------
    # Threshold experiments
    # --------------------------------------------------

    thresholds = [
    0.15,
    0.16,
    0.17,
    0.18,
    0.19,
    0.20,
    0.21,
    0.22,
    0.23,
    0.24,
    0.25,
]

    results = []

    print(
        "\n" + "=" * 70
    )

    print(
        "THRESHOLD RESULTS"
    )

    print(
        "=" * 70
    )

    for threshold in thresholds:

        # Dataset labels:
        # 0 = phishing
        # 1 = legitimate
        #
        # If phishing probability is greater
        # than or equal to threshold,
        # predict phishing (0).

        predictions = (
            phishing_probability
            >= threshold
        )

        y_pred = predictions.astype(
            int
        )

        # Convert:
        # True  -> 0 phishing
        # False -> 1 legitimate
        y_pred = 1 - y_pred

        accuracy = accuracy_score(
            y_test,
            y_pred,
        )

        phishing_precision = (
            precision_score(
                y_test,
                y_pred,
                pos_label=0,
                zero_division=0,
            )
        )

        phishing_recall = (
            recall_score(
                y_test,
                y_pred,
                pos_label=0,
                zero_division=0,
            )
        )

        phishing_f1 = (
            f1_score(
                y_test,
                y_pred,
                pos_label=0,
                zero_division=0,
            )
        )

        cm = confusion_matrix(
            y_test,
            y_pred,
            labels=[
                0,
                1,
            ],
        )

        true_positives = cm[0, 0]

        false_negatives = cm[0, 1]

        false_positives = cm[1, 0]

        true_negatives = cm[1, 1]

        result = {
            "threshold": threshold,
            "accuracy": accuracy,
            "phishing_precision": (
                phishing_precision
            ),
            "phishing_recall": (
                phishing_recall
            ),
            "phishing_f1": (
                phishing_f1
            ),
            "false_positives": (
                false_positives
            ),
            "false_negatives": (
                false_negatives
            ),
            "true_positives": (
                true_positives
            ),
            "true_negatives": (
                true_negatives
            ),
        }

        results.append(
            result
        )

        print(
            f"\nThreshold: "
            f"{threshold:.2f}"
        )

        print(
            f"Accuracy:              "
            f"{accuracy:.6f}"
        )

        print(
            f"Phishing Precision:    "
            f"{phishing_precision:.6f}"
        )

        print(
            f"Phishing Recall:       "
            f"{phishing_recall:.6f}"
        )

        print(
            f"Phishing F1:           "
            f"{phishing_f1:.6f}"
        )

        print(
            f"False Positives:       "
            f"{false_positives}"
        )

        print(
            f"False Negatives:       "
            f"{false_negatives}"
        )

    # --------------------------------------------------
    # Save results
    # --------------------------------------------------

    results_df = pd.DataFrame(
        results
    )

    results_df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------
    # Best F1 threshold
    # --------------------------------------------------

    best_row = results_df.loc[
        results_df[
            "phishing_f1"
        ].idxmax()
    ]

    print(
        "\n" + "=" * 70
    )

    print(
        "BEST THRESHOLD BY PHISHING F1"
    )

    print(
        "=" * 70
    )

    print(
        f"Threshold: "
        f"{best_row['threshold']:.2f}"
    )

    print(
        f"Phishing Precision: "
        f"{best_row['phishing_precision']:.6f}"
    )

    print(
        f"Phishing Recall: "
        f"{best_row['phishing_recall']:.6f}"
    )

    print(
        f"Phishing F1: "
        f"{best_row['phishing_f1']:.6f}"
    )

    print(
        f"False Positives: "
        f"{int(best_row['false_positives'])}"
    )

    print(
        f"False Negatives: "
        f"{int(best_row['false_negatives'])}"
    )

    print(
        "\nResults saved to:"
    )

    print(
        OUTPUT_FILE
    )

    print(
        "\nThreshold tuning completed."
    )


if __name__ == "__main__":
    main()