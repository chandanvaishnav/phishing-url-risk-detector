from pathlib import Path

import pandas as pd
import tldextract


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRANCO_FILE = PROJECT_ROOT / "data" / "external" / "tranco_extracted" / "top-1m.csv"
TRAINING_FILE = PROJECT_ROOT / "data" / "processed" / "phiusiiL_cleaned.csv"
VALIDATION_FILE = PROJECT_ROOT / "data" / "external" / "legitimate_validation.csv"

OUTPUT_DIR = PROJECT_ROOT / "data" / "external" / "tranco_augmented"
OUTPUT_FILE = OUTPUT_DIR / "tranco_legitimate_candidates.csv"

TARGET_COUNT = 10_000


# ---------------------------------------------------------
# Registered-domain helper
# ---------------------------------------------------------
def get_registered_domain(domain: str) -> str:
    domain = str(domain).strip().lower()

    extracted = tldextract.extract(domain)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return domain


# ---------------------------------------------------------
# Load registered domains already in PhiUSIIL
# ---------------------------------------------------------
print("Loading PhiUSIIL domains...")

training_df = pd.read_csv(
    TRAINING_FILE,
    usecols=["Domain"]
)

training_domains = {
    get_registered_domain(domain)
    for domain in training_df["Domain"].dropna()
    if str(domain).strip()
}

print(f"Registered domains in PhiUSIIL: {len(training_domains):,}")


# ---------------------------------------------------------
# Load external validation domains
# ---------------------------------------------------------
print("Loading external validation domains...")

validation_df = pd.read_csv(VALIDATION_FILE)

validation_domains = {
    get_registered_domain(domain)
    for domain in validation_df["URL"].dropna()
    if str(domain).strip()
}

print(f"Registered domains in validation set: {len(validation_domains):,}")


# ---------------------------------------------------------
# Load Tranco
# ---------------------------------------------------------
print("Loading Tranco list...")

tranco_df = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=["rank", "domain"]
)

print(f"Tranco rows: {len(tranco_df):,}")


# ---------------------------------------------------------
# Clean domains
# ---------------------------------------------------------
tranco_df["domain"] = (
    tranco_df["domain"]
    .astype(str)
    .str.strip()
    .str.lower()
)

tranco_df["registered_domain"] = tranco_df["domain"].apply(
    get_registered_domain
)

# Remove empty/invalid-looking entries
tranco_df = tranco_df[
    tranco_df["registered_domain"].str.contains(
        r"\.",
        regex=True,
        na=False
    )
]

# Remove duplicate registered domains
tranco_df = tranco_df.drop_duplicates(
    subset=["registered_domain"]
)


# ---------------------------------------------------------
# Exclude domains already used elsewhere
# ---------------------------------------------------------
before_exclusion = len(tranco_df)

tranco_df = tranco_df[
    ~tranco_df["registered_domain"].isin(training_domains)
]

after_training_exclusion = len(tranco_df)

tranco_df = tranco_df[
    ~tranco_df["registered_domain"].isin(validation_domains)
]

after_validation_exclusion = len(tranco_df)


# ---------------------------------------------------------
# Select top candidates
# ---------------------------------------------------------
augmentation_df = tranco_df.head(TARGET_COUNT).copy()

augmentation_df["URL"] = (
    "https://" + augmentation_df["registered_domain"]
)

augmentation_df["label"] = 1

augmentation_df = augmentation_df[
    ["rank", "URL", "registered_domain", "label"]
]


# ---------------------------------------------------------
# Save
# ---------------------------------------------------------
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

augmentation_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ---------------------------------------------------------
# Report
# ---------------------------------------------------------
print()
print("========== TRanco Augmentation ==========")
print(f"Original Tranco domains:       {before_exclusion:,}")
print(f"After PhiUSIIL exclusion:      {after_training_exclusion:,}")
print(f"After validation exclusion:    {after_validation_exclusion:,}")
print(f"Selected candidates:            {len(augmentation_df):,}")
print()
print(f"Output file:")
print(OUTPUT_FILE)
print()
print("First 10 candidates:")
print(augmentation_df.head(10).to_string(index=False))