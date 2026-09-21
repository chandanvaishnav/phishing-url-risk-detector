import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.features.url_features import extract_url_features


INPUT_FILE = "data/processed/phiusiiL_cleaned.csv"

RANDOM_STATE = 42
TEST_SIZE = 0.20


def get_registered_domain(url):
    """
    Get a registrable domain for grouped evaluation.
    """
    import tldextract

    extracted = tldextract.extract(url)

    if not extracted.domain:
        return url.lower()

    if extracted.suffix:
        return (
            extracted.domain
            + "."
            + extracted.suffix
        )

    return extracted.domain


def evaluate_model(
    name,
    X_train,
    X_test,
    y_train,
    y_test,
):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(
        X_test
    )

    phishing_index = list(
        model.classes_
    ).index(0)

    probabilities = model.predict_proba(
        X_test
    )[:, phishing_index]

    # Default threshold 0.50 for this experiment.
    predicted_phishing = (
        probabilities >= 0.50
    ).astype(int)

    # Convert back to original labels:
    # phishing = 0
    # legitimate = 1
    predicted_labels = (
        0
        + predicted_phishing
    )

    # When predicted_phishing == 0,
    # predicted label should be legitimate (1).
    predicted_labels = [
        0 if value == 1 else 1
        for value in predicted_phishing
    ]

    accuracy = accuracy_score(
        y_test,
        predicted_labels,
    )

    precision = precision_score(
        y_test,
        predicted_labels,
        pos_label=0,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predicted_labels,
        pos_label=0,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predicted_labels,
        pos_label=0,
        zero_division=0,
    )

    cm = confusion_matrix(
        y_test,
        predicted_labels,
        labels=[0, 1],
    )

    print(
        f"Features: {X_train.shape[1]}"
    )

    print(
        f"Accuracy:              {accuracy:.6f}"
    )

    print(
        f"Phishing Precision:    {precision:.6f}"
    )

    print(
        f"Phishing Recall:       {recall:.6f}"
    )

    print(
        f"Phishing F1:           {f1:.6f}"
    )

    print(
        "Confusion Matrix:"
    )

    print(cm)

    return {
        "model": name,
        "features": X_train.shape[1],
        "accuracy": accuracy,
        "phishing_precision": precision,
        "phishing_recall": recall,
        "phishing_f1": f1,
    }


def main():

    print(
        "\nLoading dataset..."
    )

    df = pd.read_csv(
        INPUT_FILE
    )

    print(
        f"Dataset size: {len(df)}"
    )

    print(
        "\nExtracting URL features..."
    )

    feature_rows = df["URL"].apply(
        extract_url_features
    )

    X = pd.DataFrame(
        feature_rows.tolist()
    )

    y = df["label"]

    print(
        f"Feature shape: {X.shape}"
    )

    print(
        "\nCreating registered-domain groups..."
    )

    groups = df["URL"].apply(
        get_registered_domain
    )

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )

    train_idx, test_idx = next(
        splitter.split(
            X,
            y,
            groups,
        )
    )

    X_train_all = X.iloc[
        train_idx
    ]

    X_test_all = X.iloc[
        test_idx
    ]

    y_train = y.iloc[
        train_idx
    ]

    y_test = y.iloc[
        test_idx
    ]

    print(
        f"Training samples: {len(X_train_all)}"
    )

    print(
        f"Testing samples: {len(X_test_all)}"
    )

    print(
        "\nTraining Model A..."
    )

    results = []

    # --------------------------------------------------
    # Model A: all features
    # --------------------------------------------------

    results.append(
        evaluate_model(
            "Model A - All 24 Features",
            X_train_all,
            X_test_all,
            y_train,
            y_test,
        )
    )

    # --------------------------------------------------
    # Model B: remove HTTPS
    # --------------------------------------------------

    features_without_https = [
        feature
        for feature in X.columns
        if feature != "IsHTTPS"
    ]

    results.append(
        evaluate_model(
            "Model B - Without IsHTTPS",
            X_train_all[
                features_without_https
            ],
            X_test_all[
                features_without_https
            ],
            y_train,
            y_test,
        )
    )

    # --------------------------------------------------
    # Model C: remove HTTPS + num_dots
    # --------------------------------------------------

    features_without_https_dots = [
        feature
        for feature in X.columns
        if feature not in [
            "IsHTTPS",
            "num_dots",
        ]
    ]

    results.append(
        evaluate_model(
            "Model C - Without IsHTTPS + num_dots",
            X_train_all[
                features_without_https_dots
            ],
            X_test_all[
                features_without_https_dots
            ],
            y_train,
            y_test,
        )
    )

    # --------------------------------------------------
    # Save comparison
    # --------------------------------------------------

    results_df = pd.DataFrame(
        results
    )

    output_file = (
        "data/processed/"
        "feature_ablation_results.csv"
    )

    results_df.to_csv(
        output_file,
        index=False,
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "ABLATION SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        results_df.to_string(
            index=False
        )
    )

    print(
        f"\nResults saved to: {output_file}"
    )


if __name__ == "__main__":
    main()
    