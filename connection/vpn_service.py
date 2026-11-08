import os
import select
import socket
import time
from threading import Lock, Thread
from typing import Optional

import bcrypt
from bson import ObjectId
from cryptography.exceptions import InvalidTag
from pymongo import MongoClient
from scapy.layers.inet import IP

from connection.database.mongodb import Account, Connection, Network
from connection.monitor import SpeedMonitor
from connection.protocol import ClientHandshake, PacketCipher, Protocol, ServerHandshake
from connection.session import NetworkAccess, Session, SessionRegistry
from connection.utils import configure_networks


class VPNServer:
    def __init__(self, mongo_client: MongoClient, table_name: str,
                 private_key: bytes or str = None):
        self.table_name = mongo_client[table_name]
        self.ip_address = '0.0.0.0'
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Keep a stable server identity around every ephemeral handshake.
        self.handshake = ServerHandshake(private_key)
        self.public_key = self.handshake.public_key.hex()
        self.max_handshakes = 1024
        self.private_key = self.handshake.private_key.hex()
        # Sessions and routes are the in-memory packet data plane.
        self.handshakes, self.registry = {}, SessionRegistry()
        self.last_cleanup = time.monotonic()
        # Transfer counters defer database writes beyond the packet path.
        self.transferred, self.transfer_lock = {}, Lock()

    def authenticate(self, credentials: tuple[str, str]):
        username, password = credentials
        collection = self.table_name['accounts']
        account = Account(collection).get(username=username)
        if not account: return None
        password_hash = account['password'].encode()
        is_correct = bcrypt.checkpw(password.encode(), password_hash)
        return account if is_correct else None

    def update_transfer(self, account_id: ObjectId or str, length: int):
        account_id = account_id.__str__()
        with self.transfer_lock:
            transferred = self.transferred.get(account_id, 0)
            self.transferred[account_id] = transferred + length

    def save_transfer(self):
        while True:
            time.sleep(1)
            self.flush_transfer()

    def flush_transfer(self):
        # Detach accumulated counters before performing all database writes.
        with self.transfer_lock:
            transferred, self.transferred = self.transferred, {}
        collection = self.table_name['accounts']
        for account_id, length in transferred.items():
            Account(collection, account_id).increment(transfer_ratio=length)

    def _network_records(self, account: dict):
        collection, records = self.table_name['networks'], []
        for network_id, options in account['networks'].items():
            if type(options) is not dict: return None
            network = Network(collection, network_id)
            details = network.get()
            if not details: return None
            mode = options.get('mode')
            if mode not in (NetworkAccess.assigned, NetworkAccess.routed):
                return None
            subnet_mask = details.get('subnet_mask')
            network_range = details.get('network_range')
            routes = details.get('routes')
            if not subnet_mask or not network_range: return None
            if type(routes) is not dict: return None
            records.append((network, details, options, mode))
        return records

    def _network_access(self, network: Network, details: dict,
                        mode: str, ip_address: str, primary: bool = False):
        routes = [f'{address}/32'
                  for address in details['routes'].values()]
        arguments = network.id, mode, ip_address, details['subnet_mask']
        arguments += details['network_range'], routes, primary
        try: return NetworkAccess(*arguments)
        except ValueError: return None

    def _assigned_accesses(self, account: dict, records: list):
        assigned = [record for record in records
                    if record[3] == NetworkAccess.assigned]
        selected = [record for record in assigned if record[2].get('primary')]
        if not assigned or len(selected) != 1: return None
        primary_record = selected[0]
        primary_id = primary_record[0].id
        networks, identities = [], {}

        for network, details, _, mode in assigned:
            connections = details.get('connections', {})
            ip_address = connections.get(account['_id'].__str__())
            if not ip_address: return None
            primary = network.id == primary_id
            access = self._network_access(network, details, mode,
                                          ip_address, primary)
            if not access: return None
            networks.append(access)
            identities[network.id.__str__()] = access
        return networks, identities, primary_id

    def _routed_accesses(self, records: list, identities: dict,
                         primary_id: ObjectId):
        networks = []
        for network, details, options, mode in records:
            if mode != NetworkAccess.routed: continue
            source_id = options.get('source')
            if not source_id: return None
            source = identities.get(source_id.__str__())
            if not source: return None
            access = self._network_access(network, details, mode,
                                          source.ip_address)
            if not access: return None
            networks.append(access)
        return networks

    def network_accesses(self, account: dict):
        # Membership modes are resolved once while the session is created.
        records = self._network_records(account)
        if not records: return None
        assigned = self._assigned_accesses(account, records)
        if not assigned: return None
        networks, identities, primary_id = assigned
        routed = self._routed_accesses(records, identities, primary_id)
        if routed is None: return None
        networks += routed

        ranges = [network.network_range for network in networks]
        if len(ranges) != len(set(ranges)): return None
        # The primary lease stays first because it configures the TUN itself.
        return sorted(networks, key=lambda network: not network.primary)

    def new_connection(self, credentials: tuple, address: tuple, keys: dict):
        # Authenticate and load every virtual network during the control phase.
        account = self.authenticate(credentials)
        if not account or not account.get('networks'): return None
        account_id = account['_id']
        networks = self.network_accesses(account)
        if not networks: return None

        # Publication replaces any older session owned by this account.
        session_id = os.urandom(16)
        cipher = PacketCipher(session_id, keys['server'], keys['client'])
        session = Session(account_id, networks, address, cipher)
        try: self.registry.add_session(session)
        except ValueError: return None

        # Persist public connection metadata without saving session keys.
        collection = self.table_name['connections']
        collection.delete_many({'account_id': account_id})
        account = Account(self.table_name['accounts'], account_id)
        Connection(collection).create(account, networks, address)
        return session

    def cleanup_handshakes(self):
        # Bound unauthenticated state retained for UDP handshakes.
        current_time = time.monotonic()
        if current_time - self.last_cleanup < 5: return
        self.last_cleanup = current_time
        for key, state in list(self.handshakes.items()):
            if current_time - state['created'] <= 15: continue
            self.handshakes.pop(key, None)

    def receive_hello(self, packet: bytes, address: tuple,
                      key: tuple, state: dict = None):
        # A repeated hello receives the same signed server response.
        if state and state.get('hello') == packet:
            self.server.sendto(state['reply'], address)
            return
        if len(self.handshakes) >= self.max_handshakes: return
        try: reply, state = self.handshake.hello(packet)
        except ValueError: return
        state['hello'] = packet
        self.handshakes[key] = state
        self.server.sendto(reply, address)

    def receive_credentials(self, packet: bytes, address: tuple,
                            state: dict):
        if state.get('configuration'):
            self.server.sendto(state['configuration'], address)
            return
        # Credentials and configuration travel inside the handshake cipher.
        try: credentials = self.handshake.credentials(packet, state)
        except (InvalidTag, UnicodeDecodeError, ValueError): return
        session = self.new_connection(credentials, address, state['keys'])
        if session:
            arguments = state, session.configurations()
            arguments += session.cipher.session_id,
            reply = self.handshake.configuration(*arguments)
        else: reply = self.handshake.error_packet(state)
        # Cache this encrypted reply so repeated UDP requests are harmless.
        state['configuration'] = reply
        self.server.sendto(reply, address)

    def receive_handshake(self, connection: tuple[bytes, any]):
        packet, address = connection
        details = Protocol.unpack(packet)
        packet_type, identifier = details[:2]
        key = address, identifier
        state = self.handshakes.get(key)

        if packet_type == Protocol.client_hello:
            self.receive_hello(packet, address, key, state)
        elif packet_type == Protocol.authentication and state:
            self.receive_credentials(packet, address, state)

    def get_destination(self, session: Session, packet: bytes):
        packet = IP(packet)
        client = self.registry.get_destination(session, packet.src, packet.dst)
        return client, packet

    def forward_packet(self, client: Session, packet: IP,
                       tunnel: bool):
        # Every destination owns independent traffic keys.
        if client:
            packet = client.cipher.encrypt(bytes(packet))
            self.server.sendto(packet, client.connection)
            self.update_transfer(client.account_id, len(packet))
        elif tunnel:
            port = getattr(packet, 'dport', 0)
            self.server.sendto(bytes(packet), (packet.dst, port))

    def send_packet(self, tunnel: bool, connection: tuple[bytes, any]):
        packet, address = connection
        session_id = Protocol.unpack(packet, Protocol.data)[1]
        session = self.registry.get_session(session_id)
        if not session: return
        # Authentication is completed before parsing the inner IP packet.
        try: packet = session.cipher.decrypt(packet)
        except (InvalidTag, ValueError): return
        try: client, packet = self.get_destination(session, packet)
        except Exception: return
        if not session.owns_address(packet.src): return
        # Valid packets may safely refresh a connection changed by NAT.
        session.connection, session.last_packet = address, time.monotonic()
        self.update_transfer(session.account_id, len(packet))
        self.forward_packet(client, packet, tunnel)

    def run_server(self, port: int = 5732, tunnel: bool = False):
        self.server.bind((self.ip_address, port))
        Thread(target=self.save_transfer, daemon=True).start()
        # Own cipher counters and packet order.
        while True:
            connection = self.server.recvfrom(65535)
            self.cleanup_handshakes()
            try: packet_type = Protocol.packet_type(connection[0])
            except ValueError: continue
            if packet_type in (Protocol.client_hello, Protocol.authentication):
                self.receive_handshake(connection)
            elif packet_type == Protocol.data:
                self.send_packet(tunnel, connection)


class VPNClient:
    def __init__(self, server_address: Optional[tuple or str] = '192.168.1.0:5732',
                 server_key: bytes or str = None):
        self.server_address, self.server_key = server_address, server_key
        self.speed_monitor = SpeedMonitor()
        if type(self.server_address) == str:
            self.server_address = server_address.split(':')
            self.server_address[1] = int(self.server_address[1])
            self.server_address = tuple(self.server_address)
        # Leave room for the UDP, protocol, counter, and authentication headers.
        self.mtu, self.cipher = 1420, None
        self.networks = []
        self.connection = [self.server_address[0], '255.255.255.0']
        self.socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def exchange(self, packet: bytes, attempts: int = 3,
                 timeout: int = 3) -> bytes:
        # Retry identical handshake packets so UDP loss is harmless.
        previous_timeout = self.socket_server.gettimeout()
        self.socket_server.settimeout(timeout)
        try:
            for _ in range(attempts):
                self.socket_server.sendto(packet, self.server_address)
                try: response, address = self.socket_server.recvfrom(65535)
                except socket.timeout: continue
                if address == self.server_address: return response
        finally: self.socket_server.settimeout(previous_timeout)
        raise TimeoutError('The server did not complete the handshake')

    def authenticate(self, username: str, password: str) -> tuple:
        # Verify server identity before placing credentials on the wire.
        handshake = ClientHandshake(self.server_key)
        packet = self.exchange(handshake.hello())
        handshake.server_hello(packet)
        packet = self.exchange(handshake.credentials(username, password))
        self.networks, self.cipher = handshake.configuration(packet)
        primary = next(network for network in self.networks if network['primary'])
        self.connection = primary['ip_address'], primary['subnet_mask']
        return self.networks

    def new_tunnel(self, interface: str):
        try: import pytun
        except ImportError:
            message = 'A TUN driver is required to connect the VPN client'
            raise RuntimeError(message)
        flags = pytun.IFF_TUN | pytun.IFF_NO_PI
        return pytun.TunTapDevice(name=interface, flags=flags)

    def connect(self, credentials: tuple, interface: str):
        tun = self.new_tunnel(interface)
        networks = self.authenticate(*credentials)
        tun.addr, tun.netmask, tun.mtu = *self.connection, self.mtu
        tun.persist(True), tun.up()
        configure_networks(interface, networks)
        self.speed_monitor.start_monitoring()
        while True:
            for source in select.select([tun, self.socket_server], [], [])[0]:
                if type(source) == pytun.TunTapDevice:
                    packet = self.cipher.encrypt(source.read(source.mtu))
                    length = self.socket_server.sendto(packet, self.server_address)
                    self.speed_monitor.update_transfer(0, length)
                    continue
                try: packet = self.cipher.decrypt(source.recvfrom(65535)[0])
                except (InvalidTag, ValueError): continue
                if len(packet) > 0:
                    self.speed_monitor.update_transfer(tun.write(packet), 0)
