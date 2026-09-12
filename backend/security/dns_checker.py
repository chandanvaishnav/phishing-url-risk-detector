import socket


def check_dns(domain: str) -> dict:
    try:
        ip_address = socket.gethostbyname(domain)

        return {
            "resolves": True,
            "ip_address": ip_address,
            "error": None
        }

    except socket.gaierror:
        return {
            "resolves": False,
            "ip_address": None,
            "error": "Domain could not be resolved"
        }

    except Exception as e:
        return {
            "resolves": False,
            "ip_address": None,
            "error": "DNS check failed"
        }