import logging
import socket
from urllib.parse import urlparse

from Backend.security.network_safety import NonPublicAddressError, resolve_public_addresses

logger = logging.getLogger("phishguard")


def _extract_hostname(value: str):
    if not value:
        return None

    candidate = str(value).strip()
    if not candidate:
        return None

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    hostname = parsed.hostname or candidate.split("/")[0].split(":")[0]
    return hostname.lower() if hostname else None


def check_dns(target: str) -> dict:
    hostname = _extract_hostname(target)
    if not hostname:
        return {
            "checked": False,
            "resolves": False,
            "ip": None,
            "hostname": None,
            "error": "Invalid hostname",
        }

    try:
        addresses = resolve_public_addresses(hostname, 0)
        return {
            "checked": True,
            "resolves": True,
            "ip": addresses[0][1][0],
            "hostname": hostname,
            "error": None,
        }
    except NonPublicAddressError as exc:
        logger.warning("Non-public DNS resolution blocked for %s", hostname)
        return {
            "checked": True,
            "resolves": False,
            "ip": None,
            "hostname": hostname,
            "error": str(exc),
        }
    except socket.gaierror:
        return {
            "checked": True,
            "resolves": False,
            "ip": None,
            "hostname": hostname,
            "error": "Domain could not be resolved",
        }
    except (socket.timeout, TimeoutError, OSError, ValueError) as exc:
        logger.warning("DNS timeout or resolution issue for %s: %s", hostname, exc)
        return {
            "checked": True,
            "resolves": False,
            "ip": None,
            "hostname": hostname,
            "error": "DNS check failed or timed out",
        }
    except Exception as exc:
        logger.exception("Unexpected DNS error for %s", hostname)
        return {
            "checked": False,
            "resolves": False,
            "ip": None,
            "hostname": hostname,
            "error": "DNS check failed",
        }