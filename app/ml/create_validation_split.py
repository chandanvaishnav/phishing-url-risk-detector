from pathlib import Path

import pandas as pd
import tldextract
from sklearn.model_selection import GroupShuffleSplit


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

BASE_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phiusiiL_plus_tranco.csv"
)

ADAPTATION_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation.csv"
)

OUTPUT_TRAIN = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_train.csv"
)

OUTPUT_VALIDATION = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_adaptation_validation.csv"
)


RANDOM_STATE = 42
VALIDATION_SIZE = 0.20


# ============================================================
# REGISTERED DOMAIN
# ============================================================

def get_registered_domain(url):
    """
    Extract the registered/root domain from a URL.

    Example:
        https://login.google.com/page
        -> google.com
    """

    try:
        extracted = tldextract.extract(str(url))

        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()

        return str(url).strip().lower()

    except Exception:
        return str(url).strip().lower()


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("CREATING PROPER DOMAIN-DISJOINT VALIDATION SET")
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # Load base training dataset
    # --------------------------------------------------------

    print("Loading base training dataset...")
    base_df = pd.read_csv(BASE_FILE, usecols=["URL", "label"])

    print(f"Base training URLs: {len(base_df):,}")

    # --------------------------------------------------------
    # Load adaptation dataset
    # --------------------------------------------------------

    print()
    print("Loading URL-Phish adaptation dataset...")
    adaptation_df = pd.read_csv(
        ADAPTATION_FILE,
        usecols=["URL", "label"]
    )

    print(f"Adaptation URLs: {len(adaptation_df):,}")

    # --------------------------------------------------------
    # Create registered domains
    # --------------------------------------------------------

    print()
    print("Extracting registered domains...")

    base_domains = set(
        base_df["URL"]
        .map(get_registered_domain)
    )

    adaptation_df["registered_domain"] = (
        adaptation_df["URL"]
        .map(get_registered_domain)
    )

    print(f"Base training domains: {len(base_domains):,}")
    print(
        "Adaptation domains:",
        adaptation_df["registered_domain"].nunique()
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Validation domains must NOT exist in base training.
    #
    # Otherwise, the model could have already seen the same
    # registered domain in PhiUSIIL + Tranco.
    # --------------------------------------------------------

    candidate_validation_df = adaptation_df[
        ~adaptation_df["registered_domain"].isin(base_domains)
    ].copy()

    print()
    print(
        "Adaptation URLs on domains unseen by base training:",
        f"{len(candidate_validation_df):,}"
    )

    print(
        "Candidate validation domains:",
        f"{candidate_validation_df['registered_domain'].nunique():,}"
    )

    if len(candidate_validation_df) == 0:
        raise RuntimeError(
            "No adaptation domains are available for validation."
        )

    # --------------------------------------------------------
    # Domain-disjoint split
    # --------------------------------------------------------

    print()
    print("Creating domain-disjoint validation split...")

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=VALIDATION_SIZE,
        random_state=RANDOM_STATE
    )

    train_idx, validation_idx = next(
        splitter.split(
            candidate_validation_df,
            candidate_validation_df["label"],
            groups=candidate_validation_df["registered_domain"]
        )
    )

    validation_domains = set(
        candidate_validation_df.iloc[
            validation_idx
        ]["registered_domain"]
    )

    # --------------------------------------------------------
    # Validation set
    # --------------------------------------------------------

    validation_df = candidate_validation_df.iloc[
        validation_idx
    ].copy()

    # --------------------------------------------------------
    # Adaptation training set
    #
    # All adaptation data except the validation domains.
    # This allows the model to use the remaining adaptation
    # data for training.
    # --------------------------------------------------------

    adaptation_train_df = adaptation_df[
        ~adaptation_df["registered_domain"].isin(validation_domains)
    ].copy()

    # --------------------------------------------------------
    # Remove helper column
    # --------------------------------------------------------

    adaptation_train_df = adaptation_train_df[
        ["URL", "label"]
    ]

    validation_df = validation_df[
        ["URL", "label"]
    ]

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    OUTPUT_TRAIN.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    adaptation_train_df.to_csv(
        OUTPUT_TRAIN,
        index=False
    )

    validation_df.to_csv(
        OUTPUT_VALIDATION,
        index=False
    )

    # --------------------------------------------------------
    # Verification
    # --------------------------------------------------------

    train_domains = set(
        adaptation_train_df["URL"]
        .map(get_registered_domain)
    )

    validation_domains_final = set(
        validation_df["URL"]
        .map(get_registered_domain)
    )

    overlap = train_domains & validation_domains_final

    base_validation_overlap = (
        validation_domains_final & base_domains
    )

    print()
    print("=" * 70)
    print("VALIDATION SPLIT RESULTS")
    print("=" * 70)

    print()
    print(f"Adaptation training URLs : {len(adaptation_train_df):,}")
    print(f"Validation URLs          : {len(validation_df):,}")

    print()
    print(
        "Adaptation training domains:",
        f"{len(train_domains):,}"
    )

    print(
        "Validation domains:",
        f"{len(validation_domains_final):,}"
    )

    print()
    print(
        "Training ↔ validation domain overlap:",
        len(overlap)
    )

    print(
        "Validation ↔ base-training domain overlap:",
        len(base_validation_overlap)
    )

    print()
    print("Training label distribution:")
    print(adaptation_train_df["label"].value_counts().to_dict())

    print()
    print("Validation label distribution:")
    print(validation_df["label"].value_counts().to_dict())

    print()
    print("Saved files:")

    print(OUTPUT_TRAIN)
    print(OUTPUT_VALIDATION)

    print()

    if len(overlap) == 0 and len(base_validation_overlap) == 0:
        print("SUCCESS: Validation domains are completely unseen.")
    else:
        print("WARNING: Domain overlap detected.")

    print("=" * 70)


if __name__ == "__main__":
    main()