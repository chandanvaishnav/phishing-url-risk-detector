from pydantic import HttpUrl


def validate_url(url: str) -> bool:
    try:
        HttpUrl(url)
        return True
    except Exception:
        return False