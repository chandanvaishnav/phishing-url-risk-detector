import socket


def check_dns(domain: str) -> dict:
    try:
        ip_address = socket.gethostbyname(domain)

        return {
            "resolves": True,
            "ip_address": ip_address
        }

    except socket.gaierror:
        return {
            "resolves": False,
            "ip_address": None
        }