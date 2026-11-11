import re
import socket
import time

from connection.egress import public

HOST = re.compile(r'^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$', re.IGNORECASE)
TIMEOUT = 5


def milliseconds(started: float) -> float:
    return round((time.monotonic() - started) * 1000, 1)


def lookup(host: str) -> dict:
    # Private answers stay hidden: they describe the server's own network.
    started = time.monotonic()
    try: answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror: return dict(error='not_found', ms=milliseconds(started))
    addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    shown = [address for address in addresses if public(address.split('%')[0])]
    return dict(addresses=shown, hidden=len(addresses) - len(shown), ms=milliseconds(started))


def connect(host: str, port: int) -> dict:
    # Same rule as the internet egress: only public destinations.
    started = time.monotonic()
    try: address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror: return dict(error='not_found', ms=milliseconds(started))
    if not public(address): return dict(error='not_public', address=address)
    started = time.monotonic()
    try: socket.create_connection((address, port), timeout=TIMEOUT).close()
    except ConnectionRefusedError: return dict(error='refused', address=address, ms=milliseconds(started))
    except socket.timeout: return dict(error='timeout', address=address, ms=milliseconds(started))
    except OSError: return dict(error='unreachable', address=address, ms=milliseconds(started))
    return dict(address=address, ms=milliseconds(started))


def request_of(body) -> tuple:
    # (tool, host, port) of a valid request, or None.
    if type(body) is not dict: return None
    tool, host, port = body.get('tool'), body.get('host'), body.get('port')
    if tool not in ('dns', 'tcp') or type(host) is not str or not HOST.match(host.strip()): return None
    if tool == 'tcp' and (type(port) is not int or not 0 < port <= 65535): return None
    return tool, host.strip().lower(), port


def run(tool: str, host: str, port: int = None) -> dict:
    # Worker thread: resolving and connecting may take seconds.
    return lookup(host) if tool == 'dns' else connect(host, port)
