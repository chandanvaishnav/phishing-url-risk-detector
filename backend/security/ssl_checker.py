import socket
import ssl
from datetime import datetime


def check_ssl(domain: str) -> dict:
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as ssl_socket:
                certificate = ssl_socket.getpeercert()

                issuer = certificate.get("issuer", [])

                issuer_info = {}

                for item in issuer:
                    for key, value in item:
                        issuer_info[key] = value

                expiry_date = datetime.strptime(
                    certificate["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                )

                return {
                    "valid": True,
                    "expires": expiry_date.strftime("%Y-%m-%d"),
                    "issuer": issuer_info
                }

    except Exception as e:
        return {
            "valid": False,
            "expires": None,
            "issuer": None,
            "error": str(e)
        }