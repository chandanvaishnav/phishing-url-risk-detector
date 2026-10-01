import logging
import socket
import ssl
from datetime import datetime
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


def check_ssl(target: str) -> dict:
    hostname = _extract_hostname(target)
    if not hostname:
        return {
            "checked": False,
            "applicable": False,
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": "Invalid hostname",
        }

    parsed = urlparse(str(target).strip())
    if parsed.scheme and parsed.scheme.lower() != "https":
        return {
            "checked": False,
            "applicable": False,
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": "SSL check not applicable for non-HTTPS URLs",
        }

    try:
        context = ssl.create_default_context()
        addresses = resolve_public_addresses(hostname, 443)
        last_connection_error = None
        for family, sockaddr in addresses:
            connection = socket.socket(family, socket.SOCK_STREAM)
            try:
                connection.settimeout(5)
                connection.connect(sockaddr)
                with context.wrap_socket(connection, server_hostname=hostname) as ssl_socket:
                    certificate = ssl_socket.getpeercert()
                    issuer = certificate.get("issuer", [])
                    issuer_info = {}
                    for item in issuer:
                        for key, value in item:
                            issuer_info[key] = value

                    expiry = certificate.get("notAfter")
                    expires = None
                    if expiry:
                        expires = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")

                    return {
                        "checked": True,
                        "applicable": True,
                        "valid": True,
                        "expires": expires,
                        "issuer": issuer_info,
                        "error": None,
                    }
            except ssl.SSLCertVerificationError:
                raise
            except (socket.timeout, TimeoutError, OSError, ConnectionError) as exc:
                last_connection_error = exc
            finally:
                connection.close()

        raise last_connection_error or OSError("No public TLS address was reachable")
    except NonPublicAddressError as exc:
        logger.warning("Non-public SSL connection blocked for %s", hostname)
        return {
            "checked": True,
            "applicable": True,
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": str(exc),
        }
    except ssl.SSLCertVerificationError:
        return {
            "checked": True,
            "applicable": True,
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": "SSL certificate verification failed",
        }
    except (socket.timeout, TimeoutError, OSError, ConnectionError, ConnectionRefusedError):
        return {
            "checked": True,
            "applicable": True,
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": "SSL connection timed out or failed",
        }
    except Exception as exc:
        logger.exception("Unexpected SSL error for %s", hostname)
        return {
            "checked": False,
            "applicable": True,
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": "SSL check failed",
        }