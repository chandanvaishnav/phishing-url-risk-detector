import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from app.features.url_features import extract_url_features


INPUT_FILE = "data/processed/phiusiiL_cleaned.csv"

TEST_URLS = [
    "https://example.com",
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
]


def main():

    print("\nLoading dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(
        f"Dataset size: {len(df)}"
    )

    print("\nExtracting features...")

    X = pd.DataFrame(
        df["URL"].apply(
            extract_url_features
        ).tolist()
    )

    y = df["label"]

    print(
        f"Feature shape: {X.shape}"
    )

    # --------------------------------------------------
    # Train Random Forest
    # --------------------------------------------------

    print("\nTraining Random Forest...")

    rf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
    )

    rf.fit(X, y)

    print("Random Forest trained.")

    # --------------------------------------------------
    # Train XGBoost
    # --------------------------------------------------

    print("\nTraining XGBoost...")

    # XGBoost uses:
    # 0 = phishing
    # 1 = legitimate

    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    xgb.fit(X, y)

    print("XGBoost trained.")

    # --------------------------------------------------
    # Test external URLs
    # --------------------------------------------------

    print("\n" + "=" * 80)
    print("EXTERNAL LEGITIMATE URL TEST")
    print("=" * 80)

    test_features = pd.DataFrame(
        [
            extract_url_features(url)
            for url in TEST_URLS
        ]
    )

    test_features = test_features[
        X.columns
    ]

    rf_predictions = rf.predict(
        test_features
    )

    rf_probabilities = rf.predict_proba(
        test_features
    )[
        :,
        list(rf.classes_).index(0),
    ]

    xgb_predictions = xgb.predict(
        test_features
    )

    xgb_probabilities = xgb.predict_proba(
        test_features
    )[
        :,
        list(xgb.classes_).index(0),
    ]

    for i, url in enumerate(
        TEST_URLS
    ):

        rf_label = (
            "phishing"
            if rf_predictions[i] == 0
            else "legitimate"
        )

        xgb_label = (
            "phishing"
            if xgb_predictions[i] == 0
            else "legitimate"
        )

        print("\nURL:", url)

        print(
            "Random Forest:",
            rf_label,
            "| phishing probability =",
            round(
                float(
                    rf_probabilities[i]
                ),
                6,
            ),
        )

        print(
            "XGBoost:",
            xgb_label,
            "| phishing probability =",
            round(
                float(
                    xgb_probabilities[i]
                ),
                6,
            ),
        )


if __name__ == "__main__":
    main()