from app.ml.explain_prediction import explain_url


TEST_URLS = [
    "https://example.com",
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
]


def main():
    print("\n" + "=" * 70)
    print("LEGITIMATE URL SANITY TEST")
    print("=" * 70)

    for url in TEST_URLS:
        try:
            result = explain_url(url)

            print("\nURL:", url)
            print("Prediction:", result["prediction"])
            print(
                "Phishing probability:",
                round(
                    result["phishing_probability"],
                    6,
                ),
            )

        except Exception as error:
            print("\nURL:", url)
            print("ERROR:", error)


if __name__ == "__main__":
    main()