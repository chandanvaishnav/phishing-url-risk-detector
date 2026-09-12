import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib


INPUT_FILE = "data/processed/url_features.csv"


def main():
    print("Loading feature dataset...")

    df = pd.read_csv(INPUT_FILE)

    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print(f"Total samples: {len(df)}")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print("Training Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    print("Model training completed.")
    print("Evaluating model...")

    y_pred = model.predict(X_test)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nFeature Importance:")

    importance = pd.Series(
        model.feature_importances_,
        index=X.columns
    ).sort_values(ascending=False)

    print(importance)
    MODEL_FILE = "models/random_forest_url_model.joblib"

    joblib.dump(model, MODEL_FILE)

    print(f"\nModel saved to: {MODEL_FILE}")


if __name__ == "__main__":
    main()