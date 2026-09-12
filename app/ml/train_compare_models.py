import joblib
import pandas as pd
import tldextract

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import (
    GroupShuffleSplit,
    train_test_split,
)

from app.features.url_features import extract_url_features


INPUT_FILE = "data/processed/phiusiiL_cleaned.csv"
FEATURE_FILE = "data/processed/url_features.csv"

RANDOM_STATE = 42
TEST_SIZE = 0.20


def get_registered_domain(url):
    """
    Return the registrable domain used for domain-grouped testing.

    Example:
        login.example.com -> example.com
    """

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    extracted = tldextract.extract(url)

    registered_domain = extracted.top_domain_under_public_suffix

    if registered_domain:
        return registered_domain.lower()

    hostname = extracted.fqdn

    return hostname.lower()


def build_feature_dataset(df):
    """
    Extract our own deployable URL-only features.
    """

    print("Extracting URL-only features...")

    feature_rows = df["URL"].apply(
        extract_url_features
    )

    features_df = pd.DataFrame(
        feature_rows.tolist()
    )

    features_df["label"] = df["label"].values

    return features_df


def train_model(X_train, y_train):
    """
    Train a controlled Random Forest model.
    """

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(
        X_train,
        y_train,
    )

    return model


def evaluate_model(model, X_test, y_test):
    """
    Calculate security-focused metrics.

    Label 0 = phishing.
    """

    predictions = model.predict(X_test)

    phishing_precision = precision_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0,
    )

    phishing_recall = recall_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0,
    )

    phishing_f1 = f1_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0,
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    )

    return {
        "accuracy": accuracy,
        "phishing_precision": phishing_precision,
        "phishing_recall": phishing_recall,
        "phishing_f1": phishing_f1,
        "confusion_matrix": matrix,
    }


def print_metrics(
    model_name,
    split_name,
    metrics,
):
    print("\n" + "=" * 70)
    print(f"{model_name} — {split_name}")
    print("=" * 70)

    print(
        f"Accuracy:              "
        f"{metrics['accuracy']:.6f}"
    )

    print(
        f"Phishing Precision:    "
        f"{metrics['phishing_precision']:.6f}"
    )

    print(
        f"Phishing Recall:       "
        f"{metrics['phishing_recall']:.6f}"
    )

    print(
        f"Phishing F1:           "
        f"{metrics['phishing_f1']:.6f}"
    )

    print("\nConfusion Matrix")
    print(
        "[[Phishing predicted as Phishing, "
        "Phishing predicted as Legitimate],"
    )
    print(
        " [Legitimate predicted as Phishing, "
        "Legitimate predicted as Legitimate]]"
    )

    print(metrics["confusion_matrix"])


def main():

    print("Loading cleaned dataset...")

    df = pd.read_csv(
        INPUT_FILE
    )

    print(
        f"Dataset size: {len(df)} URLs"
    )

    # ---------------------------------------------------------
    # Build our own URL-only feature dataset
    # ---------------------------------------------------------

    features_df = build_feature_dataset(
        df
    )

    features_df.to_csv(
        FEATURE_FILE,
        index=False,
    )

    print(
        f"\nFeature dataset saved to: "
        f"{FEATURE_FILE}"
    )

    print(
        f"Feature dataset shape: "
        f"{features_df.shape}"
    )

    # ---------------------------------------------------------
    # Prepare target
    # ---------------------------------------------------------

    X_all = features_df.drop(
        columns=["label"]
    )

    y = features_df["label"]

    # ---------------------------------------------------------
    # Create registered-domain groups
    # ---------------------------------------------------------

    print(
        "\nCreating registered-domain groups..."
    )

    groups = df["URL"].apply(
        get_registered_domain
    )

    print(
        f"Unique registered domains: "
        f"{groups.nunique()}"
    )

    # ---------------------------------------------------------
    # Two model variants
    # ---------------------------------------------------------

    feature_sets = {
        "RF_All_Features": list(
            X_all.columns
        ),
        "RF_Without_HTTPS": [
            column
            for column in X_all.columns
            if column != "IsHTTPS"
        ],
    }

    results = []

    saved_models = {}

    # ---------------------------------------------------------
    # RANDOM SPLIT
    # ---------------------------------------------------------

    print(
        "\n\n"
        + "#" * 70
    )

    print("RANDOM SPLIT EVALUATION")

    print(
        "#" * 70
    )

    random_train_idx, random_test_idx = (
        train_test_split(
            range(len(df)),
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        )
    )

    for model_name, columns in feature_sets.items():

        print(
            f"\nTraining {model_name}..."
        )

        X_train = X_all.iloc[
            random_train_idx
        ][columns]

        X_test = X_all.iloc[
            random_test_idx
        ][columns]

        y_train = y.iloc[
            random_train_idx
        ]

        y_test = y.iloc[
            random_test_idx
        ]

        model = train_model(
            X_train,
            y_train,
        )

        metrics = evaluate_model(
            model,
            X_test,
            y_test,
        )

        print_metrics(
            model_name,
            "Random Split",
            metrics,
        )

        results.append(
            {
                "model": model_name,
                "split": "random",
                "accuracy": metrics["accuracy"],
                "phishing_precision": metrics[
                    "phishing_precision"
                ],
                "phishing_recall": metrics[
                    "phishing_recall"
                ],
                "phishing_f1": metrics[
                    "phishing_f1"
                ],
            }
        )

    # ---------------------------------------------------------
    # REGISTERED-DOMAIN SPLIT
    # ---------------------------------------------------------

    print(
        "\n\n"
        + "#" * 70
    )

    print(
        "UNSEEN REGISTERED-DOMAIN EVALUATION"
    )

    print(
        "#" * 70
    )

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )

    train_idx, test_idx = next(
        splitter.split(
            X_all,
            y,
            groups=groups,
        )
    )

    train_domains = set(
        groups.iloc[train_idx]
    )

    test_domains = set(
        groups.iloc[test_idx]
    )

    overlap = train_domains.intersection(
        test_domains
    )

    print(
        f"\nTraining samples: {len(train_idx)}"
    )

    print(
        f"Testing samples: {len(test_idx)}"
    )

    print(
        f"Training domains: {len(train_domains)}"
    )

    print(
        f"Testing domains: {len(test_domains)}"
    )

    print(
        f"Domain overlap: {len(overlap)}"
    )

    if overlap:
        raise RuntimeError(
            "Registered-domain leakage detected."
        )

    for model_name, columns in feature_sets.items():

        print(
            f"\nTraining {model_name}..."
        )

        X_train = X_all.iloc[
            train_idx
        ][columns]

        X_test = X_all.iloc[
            test_idx
        ][columns]

        y_train = y.iloc[
            train_idx
        ]

        y_test = y.iloc[
            test_idx
        ]

        model = train_model(
            X_train,
            y_train,
        )

        metrics = evaluate_model(
            model,
            X_test,
            y_test,
        )

        print_metrics(
            model_name,
            "Unseen Registered Domains",
            metrics,
        )

        results.append(
            {
                "model": model_name,
                "split": "unseen_domain",
                "accuracy": metrics["accuracy"],
                "phishing_precision": metrics[
                    "phishing_precision"
                ],
                "phishing_recall": metrics[
                    "phishing_recall"
                ],
                "phishing_f1": metrics[
                    "phishing_f1"
                ],
            }
        )

        saved_models[
            model_name
        ] = model

    # ---------------------------------------------------------
    # Save comparison results
    # ---------------------------------------------------------

    results_df = pd.DataFrame(
        results
    )

    results_df.to_csv(
        "data/processed/model_comparison.csv",
        index=False,
    )

    print(
        "\n\nModel comparison saved to:"
    )

    print(
        "data/processed/model_comparison.csv"
    )

    # ---------------------------------------------------------
    # Save models trained on unseen-domain training data
    # ---------------------------------------------------------

    print(
        "\nSaving models..."
    )

    for model_name, model in saved_models.items():

        if model_name == "RF_All_Features":
            output_file = (
                "models/"
                "random_forest_url_all_features.joblib"
            )

        else:
            output_file = (
                "models/"
                "random_forest_url_no_https.joblib"
            )

        joblib.dump(
            model,
            output_file,
        )

        print(
            f"Saved: {output_file}"
        )

    # ---------------------------------------------------------
    # Final comparison
    # ---------------------------------------------------------

    print(
        "\n\n"
        + "#" * 70
    )

    print(
        "FINAL COMPARISON"
    )

    print(
        "#" * 70
    )

    display_columns = [
        "model",
        "split",
        "accuracy",
        "phishing_precision",
        "phishing_recall",
        "phishing_f1",
    ]

    print(
        results_df[
            display_columns
        ].to_string(index=False)
    )

    print(
        "\nTraining experiment completed."
    )


if __name__ == "__main__":
    main()