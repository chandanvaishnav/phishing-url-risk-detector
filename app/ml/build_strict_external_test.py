from pathlib import Path

import pandas as pd
import tldextract


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

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_external_test.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "external"
    / "urlphish_strict_external_test.csv"
)


def get_registered_domain(url):
    try:
        extracted = tldextract.extract(str(url).strip())

        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()

        return str(url).strip().lower()

    except Exception:
        return str(url).strip().lower()


def main():

    print("Loading base PhiUSIIL + Tranco training data...")
    base = pd.read_csv(BASE_FILE)

    print(f"Base URLs: {len(base):,}")

    print()
    print("Loading URL-Phish adaptation data...")
    adaptation = pd.read_csv(ADAPTATION_FILE)

    print(f"Adaptation URLs: {len(adaptation):,}")

    print()
    print("Loading original external test...")
    test = pd.read_csv(TEST_FILE)

    print(f"Original external test URLs: {len(test):,}")

    # --------------------------------------------------------
    # Extract registered domains from training data
    # --------------------------------------------------------

    print()
    print("Extracting training registered domains...")

    base_domains = set(
        base["URL"].astype(str).apply(get_registered_domain)
    )

    adaptation_domains = set(
        adaptation["URL"].astype(str).apply(get_registered_domain)
    )

    training_domains = (
        base_domains | adaptation_domains
    )

    training_domains.discard("")

    print(
        f"Combined training domains: "
        f"{len(training_domains):,}"
    )

    # --------------------------------------------------------
    # Find external URLs whose domains are unseen
    # --------------------------------------------------------

    print()
    print("Filtering external test URLs...")

    test["registered_domain"] = (
        test["URL"]
        .astype(str)
        .apply(get_registered_domain)
    )

    strict_test = test[
        ~test["registered_domain"].isin(training_domains)
    ].copy()

    # --------------------------------------------------------
    # Remove duplicate URLs
    # --------------------------------------------------------

    before_duplicates = len(strict_test)

    strict_test = strict_test.drop_duplicates(
        subset=["URL"]
    ).copy()

    duplicates_removed = (
        before_duplicates - len(strict_test)
    )

    # --------------------------------------------------------
    # Remove helper column
    # --------------------------------------------------------

    strict_test = strict_test[
        ["URL", "label"]
    ]

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    strict_test.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("STRICT EXTERNAL TEST DATASET")
    print("=" * 60)

    print(
        f"Original test URLs:       {len(test):,}"
    )

    print(
        f"Strict test URLs:         {len(strict_test):,}"
    )

    print(
        f"Removed overlapping URLs: "
        f"{len(test) - len(strict_test):,}"
    )

    print(
        f"Duplicate URLs removed:   "
        f"{duplicates_removed:,}"
    )

    print()
    print("Label distribution:")

    print(
        strict_test["label"].value_counts().to_dict()
    )

    # --------------------------------------------------------
    # Verify zero domain overlap
    # --------------------------------------------------------

    strict_domains = set(
        strict_test["URL"]
        .astype(str)
        .apply(get_registered_domain)
    )

    remaining_overlap = (
        strict_domains & training_domains
    )

    print()
    print(
        f"Strict test registered domains: "
        f"{len(strict_domains):,}"
    )

    print(
        f"Remaining training-domain overlap: "
        f"{len(remaining_overlap):,}"
    )

    if remaining_overlap:

        print()
        print("WARNING: Domain overlap still exists.")

        for domain in sorted(
            remaining_overlap
        )[:50]:
            print(domain)

    else:

        print()
        print("=" * 60)
        print("SUCCESS: ZERO REGISTERED-DOMAIN OVERLAP")
        print("=" * 60)

    print()
    print(f"Saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()