import re
from urllib.parse import urlparse, urlunsplit

import tldextract


# Use tldextract's bundled suffix snapshot; URL analysis stays offline.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def normalize_url_for_features(url: str) -> str:
    """Normalize URL components consistently with Sumit's training features."""
    value = str(url).strip()
    parse_url = value
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_url):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    netloc = ""

    if parsed.username is not None:
        netloc += parsed.username
        if parsed.password is not None:
            netloc += ":" + parsed.password
        netloc += "@"

    if hostname:
        netloc += f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname

    try:
        if parsed.port is not None:
            netloc += ":" + str(parsed.port)
    except ValueError:
        pass

    path = "" if parsed.path == "/" else parsed.path
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def extract_url_features(url: str) -> dict:
    """Extract Sumit's 25 URL-only features without making network requests."""
    feature_url = normalize_url_for_features(str(url).strip())
    parsed_url = urlparse(feature_url)
    domain = parsed_url.hostname.lower() if parsed_url.hostname else ""
    extracted = _TLD_EXTRACT(domain)
    subdomain = extracted.subdomain
    subdomain_parts = [part for part in subdomain.split(".") if part]

    url_length = len(feature_url)
    domain_length = len(domain)
    is_domain_ip = int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)))
    tld = extracted.suffix.lower() if extracted.suffix else ""
    tld_length = len(tld)
    subdomain_count = len(subdomain_parts)
    is_www_subdomain = int(subdomain.lower() == "www")

    if is_domain_ip or not domain:
        subdomain_count = 0
        is_www_subdomain = 0

    letters = sum(character.isalpha() for character in feature_url)
    digits = sum(character.isdigit() for character in feature_url)
    obfuscated_chars = len(re.findall(r"%[0-9a-fA-F]{2}", feature_url))
    has_obfuscation = int(obfuscated_chars > 0)
    other_special_chars = sum(not character.isalnum() for character in feature_url)

    letter_ratio = letters / url_length if url_length else 0
    digit_ratio = digits / url_length if url_length else 0
    obfuscation_ratio = obfuscated_chars / url_length if url_length else 0
    special_char_ratio = other_special_chars / url_length if url_length else 0

    suspicious_keywords = (
        "login", "verify", "secure", "account", "update", "password", "signin", "bank"
    )
    url_lower = feature_url.lower()

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": obfuscated_chars,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": feature_url.count("="),
        "NoOfQMarkInURL": feature_url.count("?"),
        "NoOfAmpersandInURL": feature_url.count("&"),
        "NoOfOtherSpecialCharsInURL": other_special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": int(parsed_url.scheme.lower() == "https"),
        "path_length": len(parsed_url.path),
        "query_length": len(parsed_url.query),
        "num_dots": feature_url.count("."),
        "has_at_symbol": int("@" in feature_url),
        "has_hyphen_in_domain": int("-" in domain),
        "suspicious_keyword_count": sum(keyword in url_lower for keyword in suspicious_keywords),
        "IsWWWSubdomain": is_www_subdomain,
    }
