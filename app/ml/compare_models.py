import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier


FEATURE_FILE = "data/processed/url_features.csv"
ORIGINAL_FILE = "data/processed/phiusiiL_cleaned.csv"

RANDOM_STATE = 42


def get_domain(url):
    from urllib.parse import urlparse

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    return parsed.netloc.split("@")[-1].split(":")[0].lower()


def load_data():
    print("Loading feature dataset...")
    features_df = pd.read_csv(FEATURE_FILE)

    print("Loading original URL dataset...")
    original_df = pd.read_csv(
        ORIGINAL_FILE,
        usecols=["URL"],
    )

    if len(features_df) != len(original_df):
        raise ValueError(
            "Feature dataset and original dataset have different row counts."
        )

    features_df["domain_group"] = original_df["URL"].apply(get_domain)

    X = features_df.drop(
        columns=["label", "domain_group"]
    )

    y = features_df["label"]

    groups = features_df["domain_group"]

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=RANDOM_STATE,
    )

    train_idx, test_idx = next(
        splitter.split(X, y, groups=groups)
    )

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])

    overlap = train_domains.intersection(test_domains)

    print(f"Total samples: {len(features_df)}")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print(f"Training domains: {len(train_domains)}")
    print(f"Testing domains: {len(test_domains)}")
    print(f"Domain overlap: {len(overlap)}")

    return X_train, X_test, y_train, y_test


def evaluate_model(
    name,
    model,
    X_train,
    X_test,
    y_train,
    y_test,
):
    print(f"\nTraining {name}...")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    result = {
        "Model": name,
        "Accuracy": accuracy_score(
            y_test,
            predictions,
        ),
        "Phishing Precision": precision_score(
            y_test,
            predictions,
            pos_label=0,
            zero_division=0,
        ),
        "Phishing Recall": recall_score(
            y_test,
            predictions,
            pos_label=0,
            zero_division=0,
        ),
        "Phishing F1": f1_score(
            y_test,
            predictions,
            pos_label=0,
            zero_division=0,
        ),
    }

    print(f"{name} completed.")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )

    return result


def main():
    print("Starting unseen-domain evaluation...")

    X_train, X_test, y_train, y_test = load_data()

    models = [
        (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=200,
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        ),
        (
            "XGBoost",
            XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=RANDOM_STATE,
                n_jobs=-1,
                eval_metric="logloss",
            ),
        ),
    ]

    results = []

    for name, model in models:
        result = evaluate_model(
            name,
            model,
            X_train,
            X_test,
            y_train,
            y_test,
        )

        results.append(result)

    results_df = pd.DataFrame(results)

    print("\n===== UNSEEN-DOMAIN MODEL COMPARISON =====")
    print(results_df.to_string(index=False))


if __name__ == "__main__":
    main()