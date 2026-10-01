import ipaddress
import re
from urllib.parse import urlparse


def validate_url(url: str) -> bool:
    if not isinstance(url, str):
        return False

    value = url.strip()
    if not value:
        return False

    try:
        parsed = urlparse(value)
    except Exception:
        return False

    if parsed.scheme.lower() not in {"http", "https"}:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    if hostname.lower() == "localhost":
        return True

    if "." not in hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    labels = hostname.rstrip(".").split(".")
    if len(labels) < 2:
        return False

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
    return all(label_pattern.fullmatch(label) for label in labels)