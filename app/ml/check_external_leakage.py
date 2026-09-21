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


def get_registered_domain(url):
    try:
        extracted = tldextract.extract(str(url).strip())

        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()

        return str(url).strip().lower()

    except Exception:
        return str(url).strip().lower()


def main():

    print("Loading final base training data...")
    base = pd.read_csv(BASE_FILE, usecols=["URL"])

    print(f"Base training URLs: {len(base):,}")

    print()
    print("Loading URL-Phish adaptation data...")
    adaptation = pd.read_csv(
        ADAPTATION_FILE,
        usecols=["URL"]
    )

    print(f"Adaptation URLs: {len(adaptation):,}")

    print()
    print("Loading external test data...")
    test = pd.read_csv(
        TEST_FILE,
        usecols=["URL"]
    )

    print(f"External test URLs: {len(test):,}")

    # --------------------------------------------------------
    # Registered domains
    # --------------------------------------------------------

    print()
    print("Extracting registered domains...")

    base_domains = set(
        base["URL"].apply(get_registered_domain)
    )

    adaptation_domains = set(
        adaptation["URL"].apply(get_registered_domain)
    )

    test_domains = set(
        test["URL"].apply(get_registered_domain)
    )

    # Remove empty values
    base_domains.discard("")
    adaptation_domains.discard("")
    test_domains.discard("")

    print()
    print("=" * 60)
    print("REGISTERED-DOMAIN LEAKAGE CHECK")
    print("=" * 60)

    print()
    print(f"Base training domains:       {len(base_domains):,}")
    print(f"Adaptation training domains: {len(adaptation_domains):,}")
    print(f"External test domains:       {len(test_domains):,}")

    # --------------------------------------------------------
    # Base vs test
    # --------------------------------------------------------

    base_test_overlap = (
        base_domains & test_domains
    )

    # --------------------------------------------------------
    # Adaptation vs test
    # --------------------------------------------------------

    adaptation_test_overlap = (
        adaptation_domains & test_domains
    )

    # --------------------------------------------------------
    # Combined training vs test
    # --------------------------------------------------------

    combined_training_domains = (
        base_domains | adaptation_domains
    )

    combined_test_overlap = (
        combined_training_domains & test_domains
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print()
    print("Base training ↔ External test:")
    print(
        f"Overlap domains: {len(base_test_overlap):,}"
    )

    print()
    print("Adaptation training ↔ External test:")
    print(
        f"Overlap domains: {len(adaptation_test_overlap):,}"
    )

    print()
    print("Combined training ↔ External test:")
    print(
        f"Overlap domains: {len(combined_test_overlap):,}"
    )

    # --------------------------------------------------------
    # Show overlapping domains if any
    # --------------------------------------------------------

    if combined_test_overlap:

        print()
        print("WARNING: External test contains domains")
        print("that also occur in the training data.")

        print()
        print("Overlapping domains:")

        for domain in sorted(combined_test_overlap)[:100]:
            print(domain)

        if len(combined_test_overlap) > 100:
            print(
                f"... and "
                f"{len(combined_test_overlap) - 100:,} more."
            )

    else:

        print()
        print("=" * 60)
        print("RESULT: ZERO REGISTERED-DOMAIN OVERLAP")
        print("=" * 60)

        print()
        print(
            "The external test domains are unseen relative "
            "to the combined training data."
        )

    # --------------------------------------------------------
    # Exact URL overlap
    # --------------------------------------------------------

    base_urls = set(
        base["URL"].astype(str).str.strip().str.lower()
    )

    adaptation_urls = set(
        adaptation["URL"].astype(str).str.strip().str.lower()
    )

    test_urls = set(
        test["URL"].astype(str).str.strip().str.lower()
    )

    combined_training_urls = (
        base_urls | adaptation_urls
    )

    exact_overlap = (
        combined_training_urls & test_urls
    )

    print()
    print("=" * 60)
    print("EXACT URL OVERLAP CHECK")
    print("=" * 60)

    print(
        f"Exact URLs overlapping: {len(exact_overlap):,}"
    )

    if exact_overlap:

        print()
        print("Overlapping URLs:")

        for url in sorted(exact_overlap)[:50]:
            print(url)

    else:

        print()
        print("RESULT: ZERO EXACT URL OVERLAP")


if __name__ == "__main__":
    main()