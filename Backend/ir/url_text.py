import re
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        if not scheme or not hostname:
            return ""
        try:
            port = parsed.port
        except ValueError:
            return ""
        netloc = hostname
        if port is not None and not (scheme == "https" and port == 443) and not (scheme == "http" and port == 80):
            netloc = f"{hostname}:{port}"
        path = parsed.path.rstrip("/")
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except ValueError:
        return ""


def tokenize_url(url: str) -> list[str]:
    normalized = normalize_url(url)
    if not normalized:
        return []
    parsed = urlsplit(normalized)
    text = " ".join((parsed.hostname or "", parsed.path, parsed.query))
    return re.findall(r"[a-z0-9]+", text.lower())
