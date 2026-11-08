import time
from ipaddress import ip_address as parse_address, ip_network

from bson import ObjectId

from connection.protocol import PacketCipher


class NetworkAccess:
    assigned, routed = 'assigned', 'routed'

    def __init__(self, network_id: ObjectId, mode: str,
                 ip_address: str, subnet_mask: str,
                 network_range: str, routes: list[str],
                 primary: bool = False):
        if mode not in (self.assigned, self.routed):
            raise ValueError('Unknown network access mode')
        address = parse_address(ip_address)
        target = ip_network(network_range, strict=False)
        invalid = address.version != 4 or target.version != 4
        invalid = invalid or str(target.netmask) != subnet_mask
        invalid = invalid or (primary and mode != self.assigned)
        if invalid: raise ValueError('Invalid network access configuration')
        routes = [ip_network(route, strict=False) for route in routes]
        if any(route.version != 4 for route in routes):
            raise ValueError('Invalid network access configuration')
        self.network_id, self.mode = network_id, mode
        self.primary, self.network_range = primary, target.__str__()
        self.routes = [route.__str__() for route in routes]
        self.ip_address, self.subnet_mask = ip_address, subnet_mask

    def configuration(self) -> dict:
        return dict(
            network_id=self.network_id.__str__(), mode=self.mode,
            ip_address=self.ip_address, subnet_mask=self.subnet_mask,
            network_range=self.network_range, primary=self.primary,
            routes=self.routes
        )


class Session:
    def __init__(self, account_id: ObjectId, networks: list[NetworkAccess],
                 connection: tuple, cipher: PacketCipher):
        self.account_id, self.connection = account_id, connection
        self.last_packet, self.cipher = time.monotonic(), cipher
        self.networks = {network.network_id: network for network in networks}
        primary = next((network for network in networks if network.primary), None)
        if not primary: raise ValueError('The session requires a primary network')
        self.subnet_mask = primary.subnet_mask
        self.network_id, self.ip_address = primary.network_id, primary.ip_address

    def owns_address(self, ip_address: str) -> bool:
        networks = self.networks.values()
        addresses = (network.ip_address for network in networks)
        return ip_address in addresses

    def configurations(self) -> list[dict]:
        return [network.configuration() for network in self.networks.values()]


class SessionRegistry:
    def __init__(self):
        # Index each session by identity, account, and every visible route.
        self.sessions, self.accounts, self.routes = {}, {}, {}

    def add_session(self, session: Session):
        # Refuse a route collision before replacing the account's old session.
        for network in session.networks.values():
            route = network.network_id, network.ip_address
            current = self.routes.get(route)
            if current and current.account_id != session.account_id:
                raise ValueError('The virtual route is already active')
        self.remove_session(session.account_id)
        session_id = session.cipher.session_id
        self.sessions[session_id] = session
        self.accounts[session.account_id] = session_id
        for network in session.networks.values():
            route = network.network_id, network.ip_address
            self.routes[route] = session

    def remove_session(self, account_id: ObjectId):
        session_id = self.accounts.pop(account_id, None)
        session = self.sessions.get(session_id)
        if not session: return
        for network in session.networks.values():
            route = network.network_id, network.ip_address
            self.routes.pop(route, None)
        self.sessions.pop(session_id, None)

    def get_session(self, session_id: bytes):
        return self.sessions.get(session_id)

    def get_route(self, network_id: ObjectId, ip_address: str):
        return self.routes.get((network_id, ip_address))

    def get_destination(self, session: Session,
                        source: str, destination: str):
        for network in session.networks.values():
            if network.ip_address != source: continue
            client = self.get_route(network.network_id, destination)
            if client: return client
