from urllib.parse import urlparse
import ipaddress


def check_url_security(url: str) -> dict:
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path
    query = parsed_url.query

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

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "has_ip_address": has_ip_address,
        "subdomain_count": subdomain_count,
        "has_at_symbol": "@" in url,
        "has_suspicious_symbol": any(
            symbol in url for symbol in ["@", "%"]
        ),
        "path_length": len(path),
        "query_length": len(query)
    }