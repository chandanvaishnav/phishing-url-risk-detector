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


# =========================================================
# FILE PATHS
# =========================================================

FEATURE_FILE = (
    "data/processed/phiusiiL_plus_tranco_features.csv"
)

URL_FILE = (
    "data/processed/phiusiiL_plus_tranco.csv"
)

COMPARISON_FILE = (
    "data/processed/augmented_model_comparison.csv"
)

MODEL_ALL_FILE = (
    "models/random_forest_url_augmented_all_features.joblib"
)

MODEL_NO_HTTPS_FILE = (
    "models/random_forest_url_augmented_no_https.joblib"
)


# =========================================================
# SETTINGS
# =========================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20


# =========================================================
# REGISTERED DOMAIN
# =========================================================

def get_registered_domain(url):
    """
    Return the registrable domain.

    Example:
        login.example.com -> example.com
    """

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    extracted = tldextract.extract(url)

    registered_domain = (
        extracted.top_domain_under_public_suffix
    )

    if registered_domain:
        return registered_domain.lower()

    hostname = extracted.fqdn

    return hostname.lower()


# =========================================================
# TRAIN MODEL
# =========================================================

def train_model(X_train, y_train):

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


# =========================================================
# EVALUATE MODEL
# =========================================================

def evaluate_model(model, X_test, y_test):

    predictions = model.predict(X_test)

    # Label 0 = phishing
    # Label 1 = legitimate

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


# =========================================================
# PRINT METRICS
# =========================================================

def print_metrics(
    model_name,
    split_name,
    metrics,
):

    print("\n" + "=" * 70)

    print(
        f"{model_name} - {split_name}"
    )

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

    print(
        metrics["confusion_matrix"]
    )


# =========================================================
# MAIN
# =========================================================

def main():

    # -----------------------------------------------------
    # Load feature dataset
    # -----------------------------------------------------

    print(
        "Loading augmented feature dataset..."
    )

    features_df = pd.read_csv(
        FEATURE_FILE
    )

    print(
        f"Feature dataset size: "
        f"{len(features_df):,} URLs"
    )

    print(
        f"Feature dataset shape: "
        f"{features_df.shape}"
    )


    # -----------------------------------------------------
    # Load URL dataset
    #
    # Needed only for registered-domain grouping.
    # -----------------------------------------------------

    print(
        "\nLoading augmented URL dataset..."
    )

    url_df = pd.read_csv(
        URL_FILE,
        usecols=["URL", "label"],
    )

    print(
        f"URL dataset size: "
        f"{len(url_df):,} URLs"
    )


    # -----------------------------------------------------
    # Verify row counts
    # -----------------------------------------------------

    if len(features_df) != len(url_df):

        raise RuntimeError(
            "Feature dataset and URL dataset "
            "have different numbers of rows."
        )


    # -----------------------------------------------------
    # Verify labels match
    # -----------------------------------------------------

    if not (
        features_df["label"].values
        == url_df["label"].values
    ).all():

        raise RuntimeError(
            "Feature labels and URL labels "
            "do not match."
        )


    print(
        "Feature/URL row alignment: OK"
    )


    # -----------------------------------------------------
    # Prepare ML features
    # -----------------------------------------------------

    X_all = features_df.drop(
        columns=["label"],
        errors="ignore",
    )

    y = features_df["label"]


    print(
        f"Number of ML features: "
        f"{X_all.shape[1]}"
    )


    print(
        "\nML features:"
    )

    print(
        list(X_all.columns)
    )


    # -----------------------------------------------------
    # Create registered-domain groups
    # -----------------------------------------------------

    print(
        "\nCreating registered-domain groups..."
    )

    groups = url_df["URL"].apply(
        get_registered_domain
    )

    print(
        f"Unique registered domains: "
        f"{groups.nunique():,}"
    )


    # =====================================================
    # MODEL VARIANTS
    # =====================================================

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


    # =====================================================
    # RANDOM SPLIT
    # =====================================================

    print(
        "\n\n"
        + "#" * 70
    )

    print(
        "RANDOM SPLIT EVALUATION"
    )

    print(
        "#" * 70
    )


    random_train_idx, random_test_idx = (
        train_test_split(
            range(len(features_df)),
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        )
    )


    print(
        f"\nTraining samples: "
        f"{len(random_train_idx):,}"
    )

    print(
        f"Testing samples: "
        f"{len(random_test_idx):,}"
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
                "accuracy": metrics[
                    "accuracy"
                ],
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


    # =====================================================
    # UNSEEN REGISTERED-DOMAIN SPLIT
    # =====================================================

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


    # -----------------------------------------------------
    # Domain leakage check
    # -----------------------------------------------------

    train_domains = set(
        groups.iloc[train_idx]
    )

    test_domains = set(
        groups.iloc[test_idx]
    )


    overlap = (
        train_domains.intersection(
            test_domains
        )
    )


    print(
        f"\nTraining samples: "
        f"{len(train_idx):,}"
    )

    print(
        f"Testing samples: "
        f"{len(test_idx):,}"
    )

    print(
        f"Training domains: "
        f"{len(train_domains):,}"
    )

    print(
        f"Testing domains: "
        f"{len(test_domains):,}"
    )

    print(
        f"Domain overlap: "
        f"{len(overlap)}"
    )


    if overlap:

        raise RuntimeError(
            "Registered-domain leakage detected."
        )


    print(
        "Domain leakage check: PASSED"
    )


    # -----------------------------------------------------
    # Train unseen-domain models
    # -----------------------------------------------------

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
                "accuracy": metrics[
                    "accuracy"
                ],
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


        # Save only the models trained on
        # the unseen-domain training portion.

        saved_models[
            model_name
        ] = model


    # =====================================================
    # SAVE COMPARISON RESULTS
    # =====================================================

    results_df = pd.DataFrame(
        results
    )


    results_df.to_csv(
        COMPARISON_FILE,
        index=False,
    )


    print(
        "\n\nModel comparison saved to:"
    )

    print(
        COMPARISON_FILE
    )


    # =====================================================
    # SAVE MODELS
    # =====================================================

    print(
        "\nSaving augmented models..."
    )


    for model_name, model in saved_models.items():

        if (
            model_name
            == "RF_All_Features"
        ):

            output_file = (
                MODEL_ALL_FILE
            )

        else:

            output_file = (
                MODEL_NO_HTTPS_FILE
            )


        joblib.dump(
            model,
            output_file,
        )


        print(
            f"Saved: {output_file}"
        )


    # =====================================================
    # FINAL COMPARISON
    # =====================================================

    print(
        "\n\n"
        + "#" * 70
    )

    print(
        "AUGMENTED MODEL COMPARISON"
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
        ].to_string(
            index=False
        )
    )


    print(
        "\nAugmented training experiment completed."
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()