import warnings
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd

from app.features.url_features import extract_url_features


warnings.filterwarnings(
    "ignore",
    message="`sklearn.utils.parallel.delayed`.*",
)

MODEL_FILE = (
    "models/random_forest_url_all_features.joblib"
)

DATA_FILE = (
    "data/processed/phiusiiL_cleaned.csv"
)

OUTPUT_FILE = (
    "data/processed/robustness_results.csv"
)

SAMPLE_SIZE = 500
RANDOM_STATE = 42


def uppercase_hostname(url):
    parts = urlsplit(url)

    if not parts.hostname:
        return None

    hostname = parts.hostname.upper()

    netloc = hostname

    try:
        if parts.port:
            netloc += f":{parts.port}"
    except ValueError:
        return None

    return urlunsplit(
        (
            parts.scheme,
            netloc,
            parts.path,
            parts.query,
            parts.fragment,
        )
    )


def uppercase_scheme(url):
    parts = urlsplit(url)

    if not parts.scheme:
        return None

    return urlunsplit(
        (
            parts.scheme.upper(),
            parts.netloc,
            parts.path,
            parts.query,
            parts.fragment,
        )
    )


def add_trailing_slash(url):
    parts = urlsplit(url)

    if (
        parts.path
        or parts.query
        or parts.fragment
    ):
        return None

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            "/",
            "",
            "",
        )
    )


def add_fragment(url):
    parts = urlsplit(url)

    if parts.fragment:
        return None

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            parts.query,
            "section",
        )
    )


def percent_encode_unreserved(url):
    parts = urlsplit(url)

    path = parts.path

    unreserved = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "-._~"
    )

    for index, character in enumerate(path):

        if character in unreserved:

            encoded = (
                "%"
                + format(
                    ord(character),
                    "02X",
                )
            )

            new_path = (
                path[:index]
                + encoded
                + path[index + 1:]
            )

            return urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    new_path,
                    parts.query,
                    parts.fragment,
                )
            )

    return None


def generate_variants(url):
    transformations = [
        (
            "uppercase_hostname",
            uppercase_hostname,
        ),
        (
            "uppercase_scheme",
            uppercase_scheme,
        ),
        (
            "trailing_slash",
            add_trailing_slash,
        ),
        (
            "fragment",
            add_fragment,
        ),
        (
            "percent_encode_unreserved",
            percent_encode_unreserved,
        ),
    ]

    variants = []

    for name, function in transformations:

        try:
            modified_url = function(url)

        except Exception:
            modified_url = None

        if (
            modified_url
            and modified_url != url
        ):
            variants.append(
                (
                    name,
                    modified_url,
                )
            )

    return variants


def build_feature_matrix(model, urls):
    """
    Extract features for many URLs and create
    one feature matrix for batch prediction.
    """

    feature_rows = []
    valid_urls = []

    for url in urls:

        try:
            features = extract_url_features(
                url
            )

            feature_rows.append(
                features
            )

            valid_urls.append(
                url
            )

        except Exception:
            continue

    feature_df = pd.DataFrame(
        feature_rows
    )

    feature_df = feature_df.reindex(
        columns=model.feature_names_in_,
        fill_value=0,
    )

    return valid_urls, feature_df


def batch_predict(model, urls):
    """
    Predict all URLs in one batch.
    """

    valid_urls, feature_df = (
        build_feature_matrix(
            model,
            urls,
        )
    )

    if feature_df.empty:
        return {}, {}

    probabilities = model.predict_proba(
        feature_df
    )

    class_to_index = {
        int(label): index
        for index, label
        in enumerate(model.classes_)
    }

    phishing_index = class_to_index[0]

    predictions = (
        model.classes_[
            probabilities.argmax(axis=1)
        ]
    )

    phishing_probabilities = (
        probabilities[:, phishing_index]
    )

    prediction_map = {}
    probability_map = {}

    for index, url in enumerate(
        valid_urls
    ):

        prediction_map[url] = int(
            predictions[index]
        )

        probability_map[url] = float(
            phishing_probabilities[index]
        )

    return (
        prediction_map,
        probability_map,
    )


def main():

    print("=" * 70)
    print("ROBUSTNESS TEST V3")
    print("=" * 70)

    print("\nLoading model...")

    model = joblib.load(
        MODEL_FILE
    )

    print(
        "Model loaded successfully."
    )

    print("\nLoading dataset...")

    df = pd.read_csv(
        DATA_FILE,
        usecols=[
            "URL",
            "label",
        ],
    )

    sample = df.sample(
        n=min(
            SAMPLE_SIZE,
            len(df),
        ),
        random_state=RANDOM_STATE,
    )

    print(
        f"Selected {len(sample)} base URLs."
    )

    # ---------------------------------------------------------
    # Generate all test URLs
    # ---------------------------------------------------------

    jobs = []
    all_urls = []

    print(
        "\nGenerating URL variants..."
    )

    for _, row in sample.iterrows():

        original_url = str(
            row["URL"]
        )

        original_label = int(
            row["label"]
        )

        variants = generate_variants(
            original_url
        )

        for (
            transformation,
            modified_url,
        ) in variants:

            jobs.append(
                {
                    "original_url": original_url,
                    "modified_url": modified_url,
                    "original_label": original_label,
                    "transformation": transformation,
                }
            )

            all_urls.append(
                original_url
            )

            all_urls.append(
                modified_url
            )

    # Remove duplicates while preserving order.
    all_urls = list(
        dict.fromkeys(
            all_urls
        )
    )

    print(
        f"Unique URLs to predict: "
        f"{len(all_urls)}"
    )

    print(
        "\nRunning batch prediction..."
    )

    prediction_map, probability_map = (
        batch_predict(
            model,
            all_urls,
        )
    )

    print(
        "Batch prediction completed."
    )

    # ---------------------------------------------------------
    # Compare original and modified URLs
    # ---------------------------------------------------------

    results = []

    for job in jobs:

        original_url = job[
            "original_url"
        ]

        modified_url = job[
            "modified_url"
        ]

        if (
            original_url
            not in prediction_map
            or modified_url
            not in prediction_map
        ):
            continue

        base_prediction = prediction_map[
            original_url
        ]

        modified_prediction = prediction_map[
            modified_url
        ]

        base_probability = probability_map[
            original_url
        ]

        modified_probability = probability_map[
            modified_url
        ]

        prediction_changed = (
            base_prediction
            != modified_prediction
        )

        probability_change = abs(
            base_probability
            - modified_probability
        )

        results.append(
            {
                "original_url": original_url,
                "modified_url": modified_url,
                "original_label": job[
                    "original_label"
                ],
                "transformation": job[
                    "transformation"
                ],
                "base_prediction": base_prediction,
                "modified_prediction": modified_prediction,
                "base_phishing_probability": (
                    base_probability
                ),
                "modified_phishing_probability": (
                    modified_probability
                ),
                "prediction_changed": (
                    prediction_changed
                ),
                "probability_change": (
                    probability_change
                ),
            }
        )

    results_df = pd.DataFrame(
        results
    )

    results_df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # ---------------------------------------------------------
    # Overall results
    # ---------------------------------------------------------

    print(
        "\n" + "=" * 70
    )
    print(
        "ROBUSTNESS RESULTS"
    )
    print(
        "=" * 70
    )

    total = len(
        results_df
    )

    flips = int(
        results_df[
            "prediction_changed"
        ].sum()
    )

    print(
        f"Total comparisons: {total}"
    )

    print(
        f"Prediction flips: {flips}"
    )

    if total > 0:

        flip_rate = (
            flips
            / total
            * 100
        )

        average_probability_change = (
            results_df[
                "probability_change"
            ].mean()
        )

        print(
            f"Prediction flip rate: "
            f"{flip_rate:.2f}%"
        )

        print(
            f"Average probability change: "
            f"{average_probability_change:.4f}"
        )

    # ---------------------------------------------------------
    # Results by transformation
    # ---------------------------------------------------------

    print(
        "\nResults by transformation:"
    )

    if not results_df.empty:

        summary = (
            results_df
            .groupby(
                "transformation"
            )
            .agg(
                comparisons=(
                    "prediction_changed",
                    "count",
                ),
                prediction_flips=(
                    "prediction_changed",
                    "sum",
                ),
                average_probability_change=(
                    "probability_change",
                    "mean",
                ),
            )
            .reset_index()
        )

        summary[
            "flip_rate_%"
        ] = (
            summary[
                "prediction_flips"
            ]
            / summary[
                "comparisons"
            ]
            * 100
        )

        print(
            summary.to_string(
                index=False
            )
        )

    # ---------------------------------------------------------
    # Show prediction flips
    # ---------------------------------------------------------

    print(
        "\nPrediction flip examples:"
    )

    flipped = results_df[
        results_df[
            "prediction_changed"
        ]
    ]

    if flipped.empty:

        print(
            "No prediction flips found."
        )

    else:

        print(
            flipped[
                [
                    "original_url",
                    "modified_url",
                    "transformation",
                    "base_prediction",
                    "modified_prediction",
                    "base_phishing_probability",
                    "modified_phishing_probability",
                ]
            ]
            .head(10)
            .to_string(
                index=False
            )
        )

    print(
        "\nDetailed results saved to:"
    )

    print(
        OUTPUT_FILE
    )

    print(
        "\nRobustness test completed."
    )


if __name__ == "__main__":
    main()