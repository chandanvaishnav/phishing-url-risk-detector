from app.features.url_features import extract_url_features

import pandas as pd
INPUT_FILE = "data/processed/phiusiiL_cleaned.csv"
OUTPUT_FILE = "data/processed/url_features.csv"


def main():
    print("Loading dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Dataset loaded: {len(df)} URLs")

    print("Extracting URL features...")

    feature_rows = df["URL"].apply(extract_url_features)

    features_df = pd.DataFrame(feature_rows.tolist())

    features_df["label"] = df["label"].values

    features_df.to_csv(OUTPUT_FILE, index=False)

    print(f"Features saved to: {OUTPUT_FILE}")
    print(f"Feature dataset shape: {features_df.shape}")


if __name__ == "__main__":
    main()