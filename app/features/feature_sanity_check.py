import pandas as pd

from app.features.url_features import extract_url_features


ORIGINAL_FILE = "data/processed/phiusiiL_cleaned.csv"


# Our reconstructed features and the corresponding
# original PhiUSIIL feature names.
FEATURE_MAP = {
    "URLLength": "URLLength",
    "DomainLength": "DomainLength",
    "IsDomainIP": "IsDomainIP",
    "TLDLength": "TLDLength",
    "NoOfSubDomain": "NoOfSubDomain",
    "HasObfuscation": "HasObfuscation",
    "NoOfObfuscatedChar": "NoOfObfuscatedChar",
    "ObfuscationRatio": "ObfuscationRatio",
    "NoOfLettersInURL": "NoOfLettersInURL",
    "LetterRatioInURL": "LetterRatioInURL",
    "NoOfDegitsInURL": "NoOfDegitsInURL",
    "DegitRatioInURL": "DegitRatioInURL",
    "NoOfEqualsInURL": "NoOfEqualsInURL",
    "NoOfQMarkInURL": "NoOfQMarkInURL",
    "NoOfAmpersandInURL": "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL": "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL": "SpacialCharRatioInURL",
    "IsHTTPS": "IsHTTPS",
}


def main():
    print("Loading dataset...")

    df = pd.read_csv(
        ORIGINAL_FILE,
        usecols=["URL", *FEATURE_MAP.values()],
    )

    print(f"Loaded {len(df)} URLs.")

    sample = df.sample(
        n=1000,
        random_state=42,
    )

    extracted_rows = sample["URL"].apply(
        extract_url_features
    )

    extracted_df = pd.DataFrame(
        extracted_rows.tolist(),
        index=sample.index,
    )

    print("\nFeature comparison")
    print("=" * 70)

    results = []

    for our_name, original_name in FEATURE_MAP.items():

        original_values = sample[original_name]
        our_values = extracted_df[our_name]

        exact_match = (
            original_values.reset_index(drop=True)
            == our_values.reset_index(drop=True)
        )

        match_rate = exact_match.mean() * 100

        results.append(
            {
                "Feature": our_name,
                "Match %": round(match_rate, 2),
            }
        )

    result_df = pd.DataFrame(results)

    print(
        result_df.to_string(index=False)
    )

    print("\nFeatures with differences")
    print("=" * 70)

    for our_name, original_name in FEATURE_MAP.items():

        original_values = sample[original_name].reset_index(
            drop=True
        )
        our_values = extracted_df[our_name].reset_index(
            drop=True
        )

        differences = original_values != our_values

        if differences.any():

            print(
                f"\n{our_name}: "
                f"{differences.sum()} / {len(sample)} differ"
            )

            comparison = pd.DataFrame(
                {
                    "Original": original_values[differences],
                    "Our": our_values[differences],
                }
            )

            print(
                comparison.head(5).to_string(
                    index=False
                )
            )

    print("\nSanity check completed.")


if __name__ == "__main__":
    main()