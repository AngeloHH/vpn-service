import time
from ipaddress import ip_address as parse_address, ip_network

from bson import ObjectId

from connection.limits import Limiter

from connection.protocol import PacketCipher


class NetworkAccess:
    assigned, routed = 'assigned', 'routed'

    def __init__(self, network_id: ObjectId, mode: str,
                 ip_address: str, subnet_mask: str,
                 network_range: str, routes: list[str],
                 primary: bool = False, server: dict = None,
                 organization_id: ObjectId = None, internet: bool = False, dns: list = None):
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
        if server:
            server_address, server_port = server.get('ip_address'), server.get('port')
            try: server_address = parse_address(server_address)
            except ValueError: raise ValueError('Invalid virtual server configuration')
            invalid = server_address not in target or type(server_port) is not int
            invalid = invalid or not 0 < server_port <= 65535
            if invalid: raise ValueError('Invalid virtual server configuration')
            server = dict(ip_address=server_address.__str__(), port=server_port)
        self.network_id, self.mode = network_id, mode
        self.primary, self.network_range = primary, target.__str__()
        self.routes = [route.__str__() for route in routes]
        self.ip_address, self.subnet_mask = ip_address, subnet_mask
        self.server, self.organization_id = server, organization_id
        # The network lets its members reach the internet through the server.
        self.internet = internet is True
        # DNS servers its members use while connected; none keeps their own.
        self.dns = list(dns or [])

    def configuration(self) -> dict:
        return dict(
            network_id=self.network_id.__str__(), mode=self.mode,
            ip_address=self.ip_address, subnet_mask=self.subnet_mask,
            network_range=self.network_range, primary=self.primary,
            routes=self.routes, server=self.server, internet=self.internet, dns=self.dns
        )


class Session:
    def __init__(self, account_id: ObjectId, connection: tuple,
                 cipher: PacketCipher):
        self.account_id, self.connection = account_id, connection
        self.last_packet, self.cipher = time.monotonic(), cipher
        # A login has no routes until the client selects a network.
        self.networks = {}
        # The last control reply answers retransmitted requests unchanged.
        self.request, self.reply = 0, None
        # Permissions are loaded on connect, never inside an HTTP request.
        self.permissions, self.username = None, None
        self.email, self.organization_id = None, None
        # Inner IP bytes received from and sent to this client.
        self.received, self.sent = 0, 0
        # Speed limits, and what they were resolved from: its role and its network.
        self.limiter, self.role_id, self.limited_network = Limiter(), None, None
        # Per-second rates (kbps), packet loss (%) and their last sample.
        self.rates, self.loss, self.connected_at = (0.0, 0.0), 0.0, None
        self.packets, self.sampled = 0, None

    @property
    def internet(self) -> bool:
        return any(network.internet for network in self.networks.values())

    def inside(self, ip_address: str) -> bool:
        # Addresses of its own networks never leave for the internet.
        address = parse_address(ip_address)
        return any(address in ip_network(prefix) for network in self.networks.values()
                   for prefix in [network.network_range, *network.routes])

    def owns_address(self, ip_address: str) -> bool:
        networks = self.networks.values()
        addresses = (network.ip_address for network in networks)
        return ip_address in addresses

    def configurations(self) -> list[dict]:
        return [network.configuration() for network in self.networks.values()]


class SessionRegistry:
    def __init__(self, released=None):
        # Index each session by identity, account, and every visible route.
        self.sessions, self.accounts, self.routes = {}, {}, {}
        # Called when a session loses its routes, to end what depended on them.
        self.released = released

    def add_session(self, session: Session):
        # A new login replaces the account's previous session and routes.
        self.remove_session(session.account_id)
        session_id = session.cipher.session_id
        self.sessions[session_id] = session
        self.accounts[session.account_id] = session_id

    def set_networks(self, session: Session, networks: list[NetworkAccess]):
        primary = [network for network in networks if network.primary]
        if len(primary) != 1: raise ValueError('The session requires a primary network')
        # Refuse a route collision before releasing the current routes.
        for network in networks:
            current = self.routes.get((network.network_id, network.ip_address))
            if current and current is not session:
                raise ValueError('The virtual route is already active')
        self.clear_networks(session)
        session.networks = {network.network_id: network for network in networks}
        for network in networks:
            self.routes[network.network_id, network.ip_address] = session

    def clear_networks(self, session: Session):
        for network in session.networks.values():
            route = network.network_id, network.ip_address
            if self.routes.get(route) is session: self.routes.pop(route)
        session.networks = {}
        if self.released: self.released(session)

    def remove_session(self, account_id: ObjectId):
        session_id = self.accounts.pop(account_id, None)
        session = self.sessions.pop(session_id, None)
        if session: self.clear_networks(session)

    def get_session(self, session_id: bytes):
        return self.sessions.get(session_id)

    def get_account(self, account_id: ObjectId):
        return self.sessions.get(self.accounts.get(account_id))

    def get_route(self, network_id: ObjectId, ip_address: str):
        return self.routes.get((network_id, ip_address))

    def get_destination(self, session: Session,
                        source: str, destination: str):
        return self.find_destination(session, source, destination)[1]

    def find_destination(self, session: Session, source: str, destination: str) -> tuple:
        # (network, session) of the member that holds the destination address.
        for network in session.networks.values():
            if network.ip_address != source: continue
            client = self.get_route(network.network_id, destination)
            if client: return network.network_id, client
        return None, None
