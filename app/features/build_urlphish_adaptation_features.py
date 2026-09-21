from pathlib import Path

import pandas as pd

from app.features.url_features import extract_url_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "external" / "urlphish_adaptation.csv"
OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_features.csv"
)


def main():
    print("Loading URL-Phish adaptation dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Dataset loaded: {len(df):,} URLs")

    print("Extracting URL features...")

    feature_rows = df["URL"].apply(extract_url_features)

    features_df = pd.DataFrame(feature_rows.tolist())

    # Keep labels exactly as they were prepared for our model:
    # 0 = phishing
    # 1 = legitimate
    features_df["label"] = df["label"].values

    features_df.to_csv(OUTPUT_FILE, index=False)

    print()
    print("========== FEATURE EXTRACTION COMPLETE ==========")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Feature dataset shape: {features_df.shape}")
    print()
    print("Number of ML features:", len(features_df.columns) - 1)
    print()
    print("Label distribution:")
    print(features_df["label"].value_counts().sort_index().to_dict())


if __name__ == "__main__":
    main()