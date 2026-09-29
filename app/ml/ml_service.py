from app.ml.ml_risk_evidence import generate_ml_evidence


def analyze_url(url: str) -> dict:
    """
    Public ML service interface.

    Raj's backend should call this function instead of
    directly loading the ML model.

    Input:
        url: URL string

    Output:
        Dictionary containing ML classification,
        probabilities, confidence, signals and explanation.
    """

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    return generate_ml_evidence(url)


if __name__ == "__main__":

    url = input(
        "Enter URL for ML service test: "
    ).strip()

    try:

        result = analyze_url(url)

        print("\nML service response:")

        import json

        print(
            json.dumps(
                result,
                indent=4
            )
        )

    except Exception as error:

        print(
            f"\nError: {error}"
        )