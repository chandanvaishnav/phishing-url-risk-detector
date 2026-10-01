import ipaddress
import socket


class NonPublicAddressError(ValueError):
    """Raised when a hostname resolves to a non-public address."""


def resolve_public_addresses(hostname: str, port: int) -> tuple[tuple[int, tuple], ...]:
    """Resolve a host and reject the whole answer if any address is non-public."""
    results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    addresses = []
    seen = set()

    for family, _socket_type, _protocol, _canonical_name, sockaddr in results:
        address = sockaddr[0]
        address_without_scope = address.split("%", 1)[0]
        ip = ipaddress.ip_address(address_without_scope)
        if not ip.is_global:
            raise NonPublicAddressError("Hostname resolves to a non-public address")

        key = (family, sockaddr)
        if key not in seen:
            seen.add(key)
            addresses.append((family, sockaddr))

    if not addresses:
        raise socket.gaierror("Hostname did not resolve")

    addresses.sort(key=lambda item: item[0] != socket.AF_INET)
    return tuple(addresses)
