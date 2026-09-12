import re
from urllib.parse import urlparse, urlunsplit


def normalize_url_for_features(url: str) -> str:
    """
    Normalize semantically equivalent URL forms
    before extracting character-based features.

    Normalizations:
    - Add temporary scheme for parsing scheme-less URLs.
    - Lowercase the scheme.
    - Lowercase the hostname.
    - Treat a root "/" path as an empty path.
    - Remove URL fragments.
    - Preserve query parameters.
    """

    url = str(url).strip()

    parse_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parse_url,
    ):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    hostname = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )

    # Rebuild netloc while preserving username/password
    # and port when present.
    netloc = ""

    if parsed.username is not None:
        netloc += parsed.username

        if parsed.password is not None:
            netloc += ":" + parsed.password

        netloc += "@"

    if hostname:
        # IPv6 addresses need brackets.
        if ":" in hostname and not hostname.startswith("["):
            netloc += "[" + hostname + "]"
        else:
            netloc += hostname

    try:
        if parsed.port is not None:
            netloc += ":" + str(parsed.port)
    except ValueError:
        pass

    # A root trailing slash is treated as equivalent
    # to having no path.
    path = parsed.path

    if path == "/":
        path = ""

    # Fragment is not part of the server request.
    fragment = ""

    normalized = urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            fragment,
        )
    )

    return normalized


def extract_url_features(url: str) -> dict:
    """
    Extract URL-only features for phishing URL detection.

    No network request is made.
    """

    original_url = str(url).strip()

    # Use normalized URL for security feature extraction.
    feature_url = normalize_url_for_features(
        original_url
    )

    parsed_url = urlparse(feature_url)

    domain = (
        parsed_url.hostname.lower()
        if parsed_url.hostname
        else ""
    )

    # --------------------------------------------------
    # Basic URL features
    # --------------------------------------------------

    url_length = len(feature_url)

    domain_length = len(domain)

    is_domain_ip = int(
        bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain,
            )
        )
    )

    tld = (
        domain.rsplit(".", 1)[-1].lower()
        if "." in domain
        else ""
    )

    tld_length = len(tld)

    if is_domain_ip or not domain:
        no_of_subdomain = 0
    else:
        domain_parts = domain.split(".")

        no_of_subdomain = max(
            len(domain_parts) - 2,
            0
        )

    # --------------------------------------------------
    # Character-level features
    # --------------------------------------------------

    letters = sum(
        character.isalpha()
        for character in feature_url
    )

    digits = sum(
        character.isdigit()
        for character in feature_url
    )

    obfuscated_chars = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            feature_url
        )
    )

    has_obfuscation = int(
        obfuscated_chars > 0
    )

    # --------------------------------------------------
    # Syntax features
    # --------------------------------------------------

    no_of_equals = feature_url.count("=")

    no_of_qmark = feature_url.count("?")

    no_of_ampersand = feature_url.count("&")

    other_special_chars = sum(
        not character.isalnum()
        for character in feature_url
    )

    # --------------------------------------------------
    # Ratios
    # --------------------------------------------------

    letter_ratio = (
        letters / url_length
        if url_length
        else 0
    )

    digit_ratio = (
        digits / url_length
        if url_length
        else 0
    )

    obfuscation_ratio = (
        obfuscated_chars / url_length
        if url_length
        else 0
    )

    special_char_ratio = (
        other_special_chars / url_length
        if url_length
        else 0
    )

    # --------------------------------------------------
    # Additional URL-only features
    # --------------------------------------------------

    path_length = len(
        parsed_url.path
    )

    query_length = len(
        parsed_url.query
    )

    num_dots = feature_url.count(".")

    has_at_symbol = int(
        "@" in feature_url
    )

    has_hyphen_in_domain = int(
        "-" in domain
    )

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "bank",
    ]

    url_lower = feature_url.lower()

    suspicious_keyword_count = sum(
        keyword in url_lower
        for keyword in suspicious_keywords
    )

    is_https = int(
        parsed_url.scheme.lower() == "https"
    )

    # --------------------------------------------------
    # Final feature dictionary
    # --------------------------------------------------

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": obfuscated_chars,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": other_special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": is_https,
        "path_length": path_length,
        "query_length": query_length,
        "num_dots": num_dots,
        "has_at_symbol": has_at_symbol,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "suspicious_keyword_count": suspicious_keyword_count,
    }