from urllib.parse import urlparse
import ipaddress


def check_url_security(url: str) -> dict:
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path
    query = parsed_url.query
    fragment = parsed_url.fragment

    # Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        has_ip_address = True
    except ValueError:
        has_ip_address = False

    # Count subdomains only for domain names
    if has_ip_address:
        subdomain_count = 0
    else:
        hostname_parts = hostname.split(".")
        subdomain_count = max(0, len(hostname_parts) - 2)

    # Count basic URL characteristics
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    digit_count = sum(character.isdigit() for character in url)

    # Count special characters
    special_char_count = sum(
        not character.isalnum() and character not in ["/", ":", "."]
        for character in url
    )

    # Count path segments
    path_segment_count = len(
        [segment for segment in path.split("/") if segment]
    )

    # Check whether the URL uses HTTPS
    uses_https = parsed_url.scheme.lower() == "https"

    # Check whether the URL specifies a port
    has_port = parsed_url.port is not None

    # Check whether the URL contains percent-encoded characters
    has_encoded_characters = "%" in url

    # Check whether the URL contains a fragment
    has_fragment = bool(fragment)

    # Suspicious words commonly seen in phishing URLs
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "password",
        "confirm",
        "authenticate",
        "banking"
    ]

    url_lower = url.lower()

    suspicious_keyword_count = sum(
        keyword in url_lower for keyword in suspicious_keywords
    )

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "has_ip_address": has_ip_address,
        "subdomain_count": subdomain_count,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "path_segment_count": path_segment_count,
        "has_at_symbol": "@" in url,
        "has_suspicious_symbol": any(
            symbol in url for symbol in ["@", "%"]
        ),
        "uses_https": uses_https,
        "has_port": has_port,
        "has_encoded_characters": has_encoded_characters,
        "has_fragment": has_fragment,
        "suspicious_keyword_count": suspicious_keyword_count,
        "path_length": len(path),
        "query_length": len(query)
    }