from pathlib import Path

import pandas as pd


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]

PHIUSIIL_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phiusiiL_cleaned.csv"
)

TRANCO_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "tranco_augmented"
    / "tranco_legitimate_candidates.csv"
)

OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

OUTPUT_FILE = (
    OUTPUT_DIR
    / "phiusiiL_plus_tranco.csv"
)


# ---------------------------------------------------------
# Load PhiUSIIL
# ---------------------------------------------------------
print("Loading PhiUSIIL cleaned dataset...")

phiusiiL = pd.read_csv(PHIUSIIL_FILE)

print(f"PhiUSIIL shape: {phiusiiL.shape}")


# ---------------------------------------------------------
# Load Tranco candidates
# ---------------------------------------------------------
print("Loading Tranco augmentation candidates...")

tranco = pd.read_csv(TRANCO_FILE)

print(f"Tranco augmentation shape: {tranco.shape}")


# ---------------------------------------------------------
# Keep only URL + label from Tranco
# ---------------------------------------------------------
tranco_data = tranco[
    ["URL", "label"]
].copy()


# ---------------------------------------------------------
# Make sure both datasets have the same columns
# ---------------------------------------------------------
missing_columns = set(phiusiiL.columns) - set(tranco_data.columns)

if missing_columns:
    print()
    print("Tranco candidates do not contain all PhiUSIIL columns.")
    print("Missing columns:")
    print(sorted(missing_columns))
    print()
    print(
        "This is expected because the Tranco candidates contain "
        "only URL and label."
    )


# ---------------------------------------------------------
# Build URL-only augmentation dataset
#
# We intentionally create only the URL column + label.
# The feature extractor will generate the 25 URL features later.
# ---------------------------------------------------------
augmentation = pd.DataFrame({
    "URL": tranco["URL"].astype(str),
    "label": tranco["label"].astype(int)
})


# ---------------------------------------------------------
# Extract only URL + label from PhiUSIIL
# ---------------------------------------------------------
phiusiiL_url_only = phiusiiL[
    ["URL", "label"]
].copy()


# ---------------------------------------------------------
# Combine datasets
# ---------------------------------------------------------
augmented = pd.concat(
    [
        phiusiiL_url_only,
        augmentation
    ],
    ignore_index=True
)


# ---------------------------------------------------------
# Remove duplicate URLs
# ---------------------------------------------------------
before_dedup = len(augmented)

augmented = augmented.drop_duplicates(
    subset=["URL"]
).reset_index(drop=True)

after_dedup = len(augmented)


# ---------------------------------------------------------
# Verify labels
# ---------------------------------------------------------
label_counts = augmented["label"].value_counts().to_dict()


# ---------------------------------------------------------
# Save
# ---------------------------------------------------------
OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

augmented.to_csv(
    OUTPUT_FILE,
    index=False
)


# ---------------------------------------------------------
# Report
# ---------------------------------------------------------
print()
print("========== AUGMENTED DATASET ==========")
print(f"Original PhiUSIIL rows:      {len(phiusiiL_url_only):,}")
print(f"Tranco candidates added:     {len(augmentation):,}")
print(f"Rows before deduplication:   {before_dedup:,}")
print(f"Rows after deduplication:    {after_dedup:,}")
print(f"Duplicates removed:          {before_dedup - after_dedup:,}")
print(f"Final label distribution:    {label_counts}")
print()
print("Output file:")
print(OUTPUT_FILE)
print()
print("First 10 rows:")
print(augmented.head(10).to_string(index=False))