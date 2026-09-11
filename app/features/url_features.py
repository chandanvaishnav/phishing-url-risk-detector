import re
from urllib.parse import urlparse


def extract_url_features(url: str) -> dict:
    """
    Extract URL-only features for phishing URL detection.
    """

    url = url.strip()

    # Add a scheme temporarily if the user omits it
    parsed_url = urlparse(
        url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
        else "http://" + url
    )

    domain = parsed_url.netloc.split("@")[-1].split(":")[0]
    path_and_query = parsed_url.path + parsed_url.query

    # Basic URL features
    url_length = len(url)
    domain_length = len(domain)

    # IP address detection
    is_domain_ip = int(
        bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))
    )

    # TLD
    tld = domain.split(".")[-1].lower() if "." in domain else ""
    tld_length = len(tld)

    # Subdomain count
    if is_domain_ip or not domain:
        no_of_subdomain = 0
    else:
        domain_parts = domain.split(".")
        no_of_subdomain = max(len(domain_parts) - 2, 0)
    # Obfuscation indicators
    obfuscated_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    has_obfuscation = int(obfuscated_chars > 0)

    # Character counts
    letters = len(re.findall(r"[A-Za-z]", url))
    digits = len(re.findall(r"\d", url))

    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")
    
    # Suspicious keyword detection
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "update", "password", "signin", "bank"
    ]

    url_lower = url.lower()
    suspicious_keyword_count = sum(
        keyword in url_lower for keyword in suspicious_keywords
    )

    # Additional URL structure features
    path_length = len(parsed_url.path)
    query_length = len(parsed_url.query)
    num_dots = url.count(".")
    has_at_symbol = int("@" in url)
    has_hyphen_in_domain = int("-" in domain)
    special_chars = len(
        
        re.findall(r"[^A-Za-z0-9]", url)
    )

    # Ratios
    letter_ratio = letters / url_length if url_length else 0
    digit_ratio = digits / url_length if url_length else 0
    obfuscation_ratio = (
        obfuscated_chars / url_length if url_length else 0
    )
    special_char_ratio = (
        special_chars / url_length if url_length else 0
    )

    # HTTPS
    is_https = int(parsed_url.scheme.lower() == "https")

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
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": is_https,
        "path_length": path_length,
        "query_length": query_length,
        "num_dots": num_dots,
        "has_at_symbol": has_at_symbol,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "suspicious_keyword_count": suspicious_keyword_count
    }