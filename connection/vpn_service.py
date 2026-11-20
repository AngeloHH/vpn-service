import hashlib
import logging
import os
import re
from collections import deque
import select
import socket
import time
from ipaddress import ip_address as parse_address, ip_network
from threading import Lock, Thread
from typing import Optional

from bson import ObjectId
from cryptography.exceptions import InvalidTag
from pymongo import MongoClient
from scapy.layers.inet import IP

from connection import __version__
from connection import srp
from connection.admin.auth import WebSessions
from connection.attempts import Attempts
from connection.errors import VPNError, describe
from connection.database.mongodb import Account, Connection, Member, Network, Organization
from connection.database.mongodb.networks import router_address
from connection.monitor import SpeedMonitor
from connection.egress import Egress
from connection.forwarding import Forwarding
from connection.firewall import Firewall
from connection.usage import Usage
from connection.events import INFO, WARN, Events
from connection.limits import QUOTAS, resolve
from connection.network_admin import NetworkAdmin
from connection.organizations import Organizations
from connection.role_admin import RoleAdmin
from connection.access_admin import AccessAdmin
from connection.security_admin import SecurityAdmin
from connection.backup_admin import BackupAdmin
from connection.protocol import (ClientHandshake, Control, PacketCipher,
                                 Protocol, ServerHandshake, Steps)
from connection.session import NetworkAccess, Session, SessionRegistry
from connection.system import MODEL, ProcessMetrics
from connection.tcp_bridge import VirtualHTTPBridge
from connection import tun as devices
from connection.utils import configure_networks, remove_networks
from connection.virtual_http import VirtualHTTPServer

logger = logging.getLogger(__name__)
USERNAME = re.compile(r'[A-Za-z0-9._-]{3,32}')
EMAIL = re.compile(r'[^@\s]{1,64}@[^@\s]+\.[^@\s]+')
# How many organizations one account may administer.
ORGANIZATIONS = 3


def exactly(text: str) -> dict:
    # The whole text, ignoring upper and lower case.
    return {'$regex': '^' + re.escape(text) + '$', '$options': 'i'}


class VPNServer:
    def __init__(self, mongo_client: MongoClient, table_name: str,
                 secret: bytes or str = None, public: bool = False,
                 internet: bool = False):
        self.table_name = mongo_client[table_name]
        # The server's own switch: without it no network can reach the internet.
        self.internet = internet
        # Public servers open registration; local ones accept added emails only.
        self.public, self.organizations = public, Organizations(self.table_name)
        self.started, self.metrics = None, {}
        self.web_sessions = WebSessions()
        # Byte totals per organization become a per-second traffic history.
        self.traffic, self.traffic_history = {}, {}
        self.last_sample, self.sample_interval = None, 1.0
        # Worker threads wake the packet loop when deferred HTTP work ends.
        self.waker = socket.socketpair()
        self.waker[1].setblocking(False)
        self.ip_address = '0.0.0.0'
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Clients know nothing beforehand: the password authenticates both sides.
        self.handshake = ServerHandshake(secret)
        self.secret = self.handshake.secret.hex()
        self.max_handshakes, self.attempts = 1024, Attempts()
        # Sessions and routes are the in-memory packet data plane.
        self.events = Events()
        self.usage = Usage(lambda: self.table_name['usage'])
        self.egress = Egress(lambda session, packet: self.deliver(session, packet, 'internet'),
                             notify=self.egress_warning)
        self.forwarding, self.firewall = Forwarding(), Firewall()
        self.handshakes, self.registry = {}, SessionRegistry(self.released)
        self.bridges = {}
        # Changes apply between loop iterations, after pending responses left.
        self.panel, self.pending_changes = None, []
        self.network_admin = NetworkAdmin(self.organizations, lambda: self.internet)
        self.role_admin = RoleAdmin(self.organizations)
        self.access_admin = AccessAdmin(self.network_admin)
        self.security_admin = SecurityAdmin(self.network_admin)
        self.backup_admin = BackupAdmin(self.network_admin, self.access_admin, self.security_admin)
        self.last_cleanup = time.monotonic()
        # Transfer counters defer database writes beyond the packet path.
        self.transferred, self.transfer_lock = {}, Lock()

    def find_account(self, username: str):
        if not USERNAME.fullmatch(username): return None
        return self.table_name['accounts'].find_one(dict(username=exactly(username)))

    def register(self, fields: dict, address: tuple) -> str or None:
        # Only a public server lets anyone in; the answer is an error code or None.
        # The new account has no networks yet: it founds an organization or waits to be added.
        if not self.public: return 'registration_closed'
        username, email = fields['username'], fields['email'].strip()
        if not USERNAME.fullmatch(username): return 'invalid_username'
        if len(email) > 254 or not EMAIL.fullmatch(email): return 'invalid_email'
        if not srp.valid(fields['srp']): return 'invalid_account'
        accounts = self.table_name['accounts']
        if accounts.find_one(dict(username=exactly(username))): return 'username_taken'
        if accounts.find_one(dict(email=exactly(email))): return 'email_taken'
        if not self.attempts.may_register(address[0]): return 'too_many_registrations'
        Account(accounts).create(username=username, email=email, srp=fields['srp'], networks={})
        return None

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
        organization_id = details.get('organization_id')
        try: return NetworkAccess(*arguments, server=details.get('server'),
                                  organization_id=organization_id,
                                  internet=self.internet and details.get('internet') is True,
                                  dns=details.get('dns') or [])
        except ValueError: return None

    def _assigned_access(self, account: dict, records: list,
                         network_id: str):
        for network, details, _, mode in records:
            selected = network.id.__str__() == network_id
            if mode != NetworkAccess.assigned or not selected: continue
            connections = details.get('connections', {})
            ip_address = connections.get(account['_id'].__str__())
            if not ip_address: return None
            return self._network_access(network, details, mode, ip_address, True)

    def _routed_accesses(self, records: list, source: NetworkAccess):
        networks, source_id = [], source.network_id.__str__()
        for network, details, options, mode in records:
            if mode != NetworkAccess.routed: continue
            if options.get('source').__str__() != source_id: continue
            access = self._network_access(network, details, mode,
                                          source.ip_address)
            if not access: return None
            networks.append(access)
        return networks

    def network_options(self, account: dict) -> list[dict]:
        # The menu identifies choices; addresses are only applied from connect.
        records, options, names = self._network_records(account) or [], [], {}
        account_id = account['_id'].__str__()
        for network, details, membership, mode in records:
            if mode != NetworkAccess.assigned: continue
            network_id = network.id.__str__()
            routed = [record[0].id.__str__() for record in records
                      if record[2].get('source').__str__() == network_id]
            ip_address = details.get('connections', {}).get(account_id)
            organization_id = details.get('organization_id')
            # Names let an interface show more than ranges; each organization is read once.
            if organization_id and organization_id not in names:
                organization = self.table_name['organizations'].find_one({'_id': organization_id}) or {}
                names[organization_id] = organization.get('name')
            options.append(dict(
                network_id=network_id, network_range=details['network_range'],
                ip_address=ip_address, routed=routed,
                default=bool(membership.get('primary')),
                organization_id=organization_id and organization_id.__str__(),
                name=details.get('name'), organization=names.get(organization_id)
            ))
        return options

    def network_accesses(self, account: dict, network_id: ObjectId or str):
        # One assigned identity plus every routed network that reuses it.
        records = self._network_records(account)
        if not records: return None
        primary = self._assigned_access(account, records, network_id.__str__())
        if not primary: return None
        routed = self._routed_accesses(records, primary)
        if routed is None: return None
        networks = [primary] + routed
        ranges = [network.network_range for network in networks]
        return networks if len(ranges) == len(set(ranges)) else None

    def add_virtual_http(self, network_id, ip_address: str = None,
                         port: int = None, server: VirtualHTTPServer = None):
        network = Network(self.table_name['networks'], network_id)
        details = network.get()
        if not details: raise ValueError('The virtual network does not exist')
        configuration = details.get('server') or {}
        ip_address = ip_address or configuration.get('ip_address') or router_address(details['network_range'])
        port = configuration.get('port', 80) if port is None else port
        if not ip_address: raise ValueError('The virtual server address is required')
        network_range = ip_network(details['network_range'], strict=False)
        address = parse_address(ip_address)
        reserved = list(details.get('connections', {}).values())
        reserved += list(details.get('routes', {}).values())
        if address not in network_range or ip_address in reserved:
            raise ValueError('The virtual server address is not available')
        if network.id in self.bridges:
            raise ValueError('The virtual network already has an HTTP server')
        bridge = VirtualHTTPBridge(network.id, ip_address, port, server)
        try: network.update(server=dict(ip_address=ip_address, port=port))
        except Exception:
            bridge.close()
            raise
        bridge.server.notify = self.wake_loop
        self.bridges[network.id] = bridge
        return bridge.server

    def close(self):
        for resource in (self.server, *self.waker): resource.close()

    def wake_loop(self):
        try: self.waker[1].send(b'\0')
        except (BlockingIOError, OSError): pass

    def get_bridge(self, session: Session, source: str, destination: str):
        for network in session.networks.values():
            if network.ip_address != source: continue
            bridge = self.bridges.get(network.network_id)
            if bridge and bridge.ip_address == destination: return bridge

    def forward_bridge(self, bridge: VirtualHTTPBridge, packets: list[bytes]):
        for packet in packets:
            if len(packet) < 20: continue
            client = self.registry.get_route(bridge.network_id, socket.inet_ntoa(packet[16:20]))
            if client: self.deliver(client, packet)

    def bridge_timeout(self):
        delays = [bridge.next_timeout() for bridge in self.bridges.values()]
        delays = [delay for delay in delays if delay is not None]
        return min(delays) if delays else None

    def advance_bridges(self):
        for bridge in list(self.bridges.values()):
            self.forward_bridge(bridge, bridge.advance())
        while self.pending_changes: self.complete_change(self.pending_changes.pop(0))

    def add_panel(self, network_id, server: VirtualHTTPServer = None):
        # Every network serves the panel at its router address.
        http = self.add_virtual_http(network_id, server=server)
        if self.panel and not server: self.panel(http, self)
        return http

    def change_panel(self, action: str, network_id):
        bridge = self.bridges.pop(network_id, None)
        if bridge: bridge.close()
        if action == 'remove' and bridge and bridge.server.executor:
            bridge.server.executor.shutdown(wait=False)
        if action == 'remove': return
        # A moved panel keeps its routes, timers and open streams' server.
        try: self.add_panel(network_id, bridge.server if bridge else None)
        except ValueError: logger.exception('The panel could not start')

    def apply_change(self, change: dict):
        # The answer leaves first: releasing routes now would strand it.
        self.pending_changes.append(change)
        self.wake_loop()

    def complete_change(self, change: dict):
        # MongoDB already holds the change; live sessions and panels follow it.
        for account_id in change.get('kick', []): self.kick(account_id)
        for account_id in change.get('disconnect', []): self.disconnect(account_id)
        for account_id, network_id in change.get('reconnect', []): self.reconnect(account_id, network_id)
        if change.get('forwards'): self.forwarding.install(*change['forwards'])
        if change.get('firewall'): self.firewall.install(*change['firewall'])
        if change.get('limits'): self.refresh_limits(change['organization_id'], *change['limits'])
        if change.get('extra'): self.usage.set_extra(*change['extra'])
        if change.get('panel'): self.change_panel(*change['panel'])
        for action, network_id in change.get('panels', []): self.change_panel(action, network_id)
        for account_id in change.get('refresh', []): self.refresh_member(change['organization_id'], account_id)

    def reconnect(self, account_id, network_id):
        # Only a session connected through that network gets a new configuration.
        session = self.registry.get_account(ObjectId(account_id.__str__()))
        primary = session and next((network for network in session.networks.values() if network.primary), None)
        if primary and primary.network_id.__str__() == network_id.__str__(): self.disconnect(account_id)

    def load_forwards(self):
        # At start: every organization's forwards and rules between members, as the panel left them.
        for organization_id in {network.get('organization_id') for network in self.table_name['networks'].find({})}:
            if not organization_id: continue
            self.forwarding.install(organization_id, self.access_admin.table(organization_id))
            self.firewall.install(organization_id, self.security_admin.table(organization_id))

    def create_organization(self, session: Session, name) -> dict:
        # Anyone with an account may found an organization and administer it.
        name = name.strip() if type(name) is str else ''
        if not 1 <= len(name) <= 40: return describe('invalid_name')
        administered = 0
        for member in self.organizations.members.find(dict(account_id=session.account_id)):
            role = member.get('role_id') and self.organizations.roles.find_one({'_id': member['role_id']})
            administered += bool(role and role.get('administrator'))
        if administered >= ORGANIZATIONS: return describe('organization_limit', limit=ORGANIZATIONS)
        organization_id, network_id = self.found(session.account_id, name)
        return dict(organization_id=organization_id.__str__(), network_id=network_id.__str__())

    def found(self, account_id, name: str) -> tuple:
        # The organization starts with its administrator, a first network and that network's panel.
        organization_id = self.organizations.create(account_id, name)
        network = self.table_name['networks'].find_one(dict(organization_id=organization_id))
        self.add_panel(network['_id'])
        self.forwarding.install(organization_id, self.access_admin.table(organization_id))
        self.firewall.install(organization_id, self.security_admin.table(organization_id))
        return organization_id, network['_id']

    def refresh_member(self, organization_id, account_id):
        # A new role or new permissions reach the open session without reconnecting it.
        session = self.registry.get_account(ObjectId(account_id.__str__()))
        if not session or session.organization_id != organization_id: return
        try: session.permissions = self.organizations.permissions(session.account_id, organization_id)
        except PermissionError: session.permissions = None
        self.apply_limits(session, session.limited_network)

    def open_session(self, account: dict, address: tuple, keys: dict) -> Session:
        # A login only opens the session; it gains routes on connect.
        session_id = os.urandom(16)
        cipher = PacketCipher(session_id, keys['server'], keys['client'])
        session = Session(account['_id'], address, cipher)
        session.username, session.email = account.get('username'), account.get('email')
        self.registry.add_session(session)
        return session

    def activate(self, session: Session, account: dict, network_id) -> dict:
        # Read the configuration now, so a stale menu never assigns an address.
        valid = type(network_id) is str and ObjectId.is_valid(network_id)
        networks = self.network_accesses(account, network_id) if valid else None
        if not networks: return describe('network_unavailable')
        blocked = networks[0].organization_id and self.organizations.is_blocked(
            session.account_id, networks[0].organization_id)
        if blocked: return describe('account_blocked')
        try: self.registry.set_networks(session, networks)
        except ValueError as error: return dict(describe('network_conflict'), message=str(error))
        # Panel permissions are cached so HTTP requests never query MongoDB.
        organization_id, session.permissions = networks[0].organization_id, None
        session.organization_id, session.connected_at = organization_id, time.monotonic()
        if organization_id:
            try: session.permissions = self.organizations.permissions(
                session.account_id, organization_id)
            except PermissionError: pass
        primary = next(network for network in networks if network.primary)
        self.apply_limits(session, primary.network_id)
        self.events.record(organization_id, INFO, 'connected', primary.network_id,
                           username=session.username, ip=primary.ip_address)

        # Persist public connection metadata without saving session keys.
        collection = self.table_name['connections']
        collection.delete_many({'account_id': session.account_id})
        account = Account(self.table_name['accounts'], session.account_id)
        Connection(collection).create(account, networks, session.connection)
        return dict(configuration=session.configurations())

    def control_reply(self, session: Session, message: dict) -> dict:
        action, reply = message.get('action'), dict(request=message['request'])
        account = Account(self.table_name['accounts'], session.account_id).get()
        if not account: reply.update(describe('account_missing'))
        elif action == Control.list_networks:
            reply.update(networks=self.network_options(account))
        elif action == Control.connect:
            reply.update(self.activate(session, account, message.get('network_id')))
        elif action == Control.create_organization:
            reply.update(self.create_organization(session, message.get('name')))
        elif action == Control.account:
            reply.update(username=account.get('username'), email=account.get('email'))
        elif action == Control.ping: pass
        else: reply.update(describe('unknown_action'))
        return reply

    def send_control(self, session: Session, message: dict):
        packet = session.cipher.encrypt(Control.pack(message), Protocol.control)
        self.server.sendto(packet, session.connection)

    def receive_control(self, connection: tuple[bytes, any]):
        packet, address = connection
        session_id = Protocol.unpack(packet, Protocol.control)[1]
        session = self.registry.get_session(session_id)
        if not session: return
        try: message = Control.unpack(session.cipher.decrypt(packet, Protocol.control))
        except (InvalidTag, ValueError): return
        session.packets += 1
        request = message.get('request')
        if type(request) is not int or request < session.request: return
        session.connection, session.last_packet = address, time.monotonic()
        # A retransmitted request receives the same reply without side effects.
        if request > session.request:
            session.request = request
            session.reply = self.control_reply(session, message)
        self.send_control(session, session.reply)

    def disconnect(self, account_id: ObjectId or str):
        # The login survives; only routes are released and the client told.
        session = self.registry.get_account(ObjectId(account_id.__str__()))
        if not session or not session.networks: return
        self.registry.clear_networks(session)
        collection = self.table_name['connections']
        collection.delete_many({'account_id': session.account_id})
        self.send_control(session, dict(action=Control.disconnected))

    def kick(self, account_id: ObjectId or str):
        # The login ends here; the client is told not to reconnect by itself.
        session = self.registry.get_account(ObjectId(account_id.__str__()))
        if not session: return
        self.send_control(session, dict(action=Control.kicked))
        self.registry.remove_session(session.account_id)
        collection = self.table_name['connections']
        collection.delete_many({'account_id': session.account_id})

    def change_account(self, account_id: ObjectId or str, change):
        # Persist first: a failed write leaves the live session untouched.
        result = change()
        self.disconnect(account_id)
        return result

    def cleanup_handshakes(self):
        # Bound unauthenticated state retained for UDP handshakes.
        current_time = time.monotonic()
        if current_time - self.last_cleanup < 5: return
        self.last_cleanup = current_time
        for key, state in list(self.handshakes.items()):
            if current_time - state['created'] <= 15: continue
            self.handshakes.pop(key, None)
        self.attempts.cleanup()

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

    def receive_authentication(self, packet: bytes, address: tuple, state: dict):
        # A repeated packet gets the same answer: UDP loss never repeats an action.
        replies = state.setdefault('replies', {})
        if packet in replies:
            self.server.sendto(replies[packet], address)
            return
        if len(replies) >= 4: return
        try: step, fields = self.handshake.request(packet, state)
        except (InvalidTag, UnicodeDecodeError, ValueError): return
        reply = self.authentication_reply(step, fields, packet, address, state)
        if reply is None: return
        replies[packet] = reply
        self.server.sendto(reply, address)

    def authentication_reply(self, step: int, fields: dict, packet: bytes, address: tuple, state: dict):
        handshake = self.handshake
        if step == Steps.register:
            if state.get('srp'): return None
            error = self.register(fields, address)
            if error: return handshake.error_packet(state, error)
            return handshake.reply(state, Protocol.registered)
        if step == Steps.login:
            if state.get('srp'): return None
            username = fields['username']
            state['tries'] = (('name', username.casefold()), ('address', address[0]))
            wait = self.attempts.blocked(state['tries'])
            if wait: return handshake.error_packet(state, 'too_many_attempts', wait=int(wait) + 1)
            state['account'] = account = self.find_account(username)
            try: return handshake.challenge(state, packet, username, (account or {}).get('srp'), fields['public'])
            except ValueError: return None
        if step != Steps.proof or not state.get('srp') or state.get('finished'): return None
        state['finished'] = True
        keys = handshake.finish(state, packet, fields['proof'])
        if not keys or not state['account']:
            self.attempts.failed(state['tries'])
            return handshake.error_packet(state)
        self.attempts.succeeded(state['tries'])
        session = self.open_session(state['account'], address, keys)
        return handshake.configuration(state, keys, session.cipher.session_id)

    def receive_handshake(self, connection: tuple[bytes, any]):
        packet, address = connection
        details = Protocol.unpack(packet)
        packet_type, identifier = details[:2]
        key = address, identifier
        state = self.handshakes.get(key)

        if packet_type == Protocol.client_hello:
            self.receive_hello(packet, address, key, state)
        elif packet_type == Protocol.authentication and state:
            self.receive_authentication(packet, address, state)

    def get_destination(self, session: Session, packet: bytes):
        packet = IP(packet)
        client = self.registry.get_destination(session, packet.src, packet.dst)
        return client, packet

    def apply_limits(self, session: Session, network_id):
        # The connection's main network decides the network limit, routed ones included.
        organization_id = session.organization_id
        member = Member(self.organizations.members).get(
            organization_id=organization_id, account_id=session.account_id) if organization_id else None
        session.role_id, session.limited_network = (member or {}).get('role_id'), network_id
        network = Network(self.table_name['networks'], network_id).get() or {}
        organization = Organization(self.table_name['organizations'], organization_id).get() or {} \
            if organization_id else {}
        session.limiter.set(resolve(network.get('limits'), session.role_id, session.account_id),
                            resolve(organization.get('internet_limits'), session.role_id, session.account_id))
        if not organization_id: return
        # The month's consumption is loaded now, so the packet path never reads MongoDB.
        account_id = session.account_id.__str__()
        keys = dict(network=(organization_id.__str__(), account_id, network_id.__str__()),
                    internet=(organization_id.__str__(), account_id, 'internet'))
        for key in keys.values(): self.usage.spent(key)
        # Extras of this month: the person's own and its role's, per scope.
        owners = [('account', account_id)] + ([('role', session.role_id.__str__())] if session.role_id else [])
        extras = {scope: [(organization_id.__str__(), kind, owner, key[2]) for kind, owner in owners]
                  for scope, key in keys.items()}
        for scope_keys in extras.values():
            for key in scope_keys: self.usage.load_extra(key)
        session.limiter.bind(self.usage, keys, lambda scope, direction: self.quota_reached(session, scope, direction),
                             extras)
        session.limiter.set_quotas(
            resolve(network.get('limits'), session.role_id, session.account_id, QUOTAS),
            resolve(organization.get('internet_limits'), session.role_id, session.account_id, QUOTAS))

    def quota_reached(self, session: Session, scope: str, direction: str):
        self.events.record(session.organization_id, WARN, 'quota_reached', session.limited_network,
                           username=session.username, scope=scope, direction=direction)

    def refresh_limits(self, organization_id, kind: str, network_id, limits: dict):
        # New limits reach connected members at once, without reconnecting them.
        for session in list(self.registry.sessions.values()):
            if session.organization_id != organization_id: continue
            values = resolve(limits, session.role_id, session.account_id)
            quotas = resolve(limits, session.role_id, session.account_id, QUOTAS)
            if kind == 'internet': session.limiter.set(internet=values), session.limiter.set_quotas(internet=quotas)
            elif session.limited_network == network_id:
                session.limiter.set(network=values), session.limiter.set_quotas(network=quotas)

    def egress_warning(self, session: Session, kind: str):
        primary = next((network for network in session.networks.values() if network.primary), None)
        self.events.record(session.organization_id, WARN, kind,
                           primary.network_id if primary else None, username=session.username)

    def deliver(self, client: Session, content: bytes, through: str = None):
        # through: 'network' or 'internet' spend the receiver's buckets; the panel does not.
        if through and not client.limiter.allow('down', len(content), through == 'internet'): return
        # Every destination owns independent traffic keys.
        packet = client.cipher.encrypt(content)
        self.server.sendto(packet, client.connection)
        self.update_transfer(client.account_id, len(packet))
        self.count_traffic(client, len(content), True)

    def send_packet(self, connection: tuple[bytes, any]):
        packet, address = connection
        session_id = Protocol.unpack(packet, Protocol.data)[1]
        session = self.registry.get_session(session_id)
        if not session: return
        # Authentication is completed before parsing the inner IP packet.
        try: raw = session.cipher.decrypt(packet)
        except (InvalidTag, ValueError): return
        session.packets += 1
        # Data without routes means the client missed a disconnection notice.
        if not session.networks:
            session.connection = address
            self.send_control(session, dict(action=Control.disconnected))
            return
        try: packet = IP(raw)
        except Exception: return
        if not session.owns_address(packet.src): return
        # Valid packets may safely refresh a connection changed by NAT.
        session.connection, session.last_packet = address, time.monotonic()
        self.update_transfer(session.account_id, len(packet))
        self.count_traffic(session, len(packet), False)
        if self.forward(session, packet.dst, raw): return
        bridge = self.get_bridge(session, packet.src, packet.dst)
        if bridge:
            try: packets = bridge.receive(bytes(packet))
            except (ValueError, ConnectionError, KeyError): return
            self.forward_bridge(bridge, packets)
            return
        network_id, client = self.registry.find_destination(session, packet.src, packet.dst)
        if client:
            # Seguridad: the network's rules between members decide first.
            if not self.firewall.allows(network_id, session, client, raw): return
            if not session.limiter.allow('up', len(raw)): return
            return self.deliver(client, bytes(packet), 'network')
        # Outside every network of the session: the internet, if a network allows it.
        if self.internet and session.internet and not session.inside(packet.dst):
            # The network limit applies first; the internet limit adds to it.
            if not session.limiter.allow('up', len(raw), True): return
            self.egress.outbound(session, raw)

    def released(self, session: Session):
        # The session lost its routes: whatever depended on them ends.
        self.egress.drop(session)
        self.forwarding.drop(session)

    def forward(self, session: Session, destination: str, raw: bytes) -> bool:
        # True when a forwarding rule, or the answer to one, took the packet.
        # Every network of a session shares its one address, already checked.
        for network in session.networks.values():
            bridge = self.bridges.get(network.network_id)
            # Answers come back to the panel address, on a translated port.
            if bridge and bridge.ip_address == destination:
                found = self.forwarding.inbound(network.network_id, raw)
                if not found: continue
                entry, packet = found
                if session.limiter.allow('up', len(raw)): self.deliver(entry.client, packet, 'network')
                return True
            if not self.forwarding.listens(network.network_id, destination): continue
            rule = self.forwarding.rule_for(network.network_id, raw)
            if rule and rule.get('target_network') is None:
                # Towards the internet: the network itself must let it out.
                if network.internet and session.limiter.allow('up', len(raw), True):
                    self.egress.outbound(session, raw, lambda protocol, reached: self.forwarding.destination(rule, reached[1]))
            elif rule:
                self.forward_inside(session, network.network_id, raw, rule)
            return True
        return False

    def forward_inside(self, session: Session, network_id, raw: bytes, rule: dict):
        bridge = self.bridges.get(rule['target_network'])
        if not bridge: return
        translated = self.forwarding.outbound(session, network_id, raw, bridge.ip_address)
        if not translated: return
        entry, packet = translated
        target = self.registry.get_route(entry.network_id, entry.target[0])
        if target and session.limiter.allow('up', len(raw)): self.deliver(target, packet, 'network')

    def count_traffic(self, session: Session, length: int, sent: bool):
        # Only additions on the packet path; rates are derived once per second.
        totals = self.traffic.setdefault(session.organization_id, [0, 0])
        totals[sent] += length
        if sent: session.sent += length
        else: session.received += length

    def sample_traffic(self, now: float = None):
        now = time.monotonic() if now is None else now
        if self.last_sample is None:
            self.last_sample = now, {key: list(value) for key, value in self.traffic.items()}
            return
        before, previous = self.last_sample
        elapsed = now - before
        if elapsed < self.sample_interval: return
        for session in self.registry.sessions.values(): self.sample_session(session, elapsed)
        # Download is what clients receive; upload is what they send, in kbps.
        for organization_id, (received, sent) in self.traffic.items():
            old_received, old_sent = previous.get(organization_id, (0, 0))
            rate = lambda delta: round(delta * 8 / 1000 / elapsed, 1)
            history = self.traffic_history.setdefault(organization_id, deque(maxlen=60))
            history.append((rate(sent - old_sent), rate(received - old_received)))
        self.last_sample = now, {key: list(value) for key, value in self.traffic.items()}

    @staticmethod
    def sample_session(session: Session, elapsed: float):
        # Gaps in the client's packet counters are packets lost on the way.
        counter = session.cipher.replay.counter
        current = session.sent, session.received, session.packets, counter
        if session.sampled:
            sent, received, packets, last = (now - before for now, before
                                             in zip(current, session.sampled))
            rate = lambda delta: round(delta * 8 / 1000 / elapsed, 1)
            session.rates = rate(sent), rate(received)
            if last > 0: session.loss = round(max(0.0, 1 - packets / last) * 100, 1)
        session.sampled = current

    def traffic_delay(self, now: float = None):
        if self.last_sample is None: return 0.0
        now = time.monotonic() if now is None else now
        return max(0.0, self.last_sample[0] + self.sample_interval - now)

    def collect_metrics(self, interval: float = 5):
        # Slow probes run here; requests only read the latest snapshot.
        metrics = ProcessMetrics()
        while True:
            time.sleep(interval)
            self.metrics = metrics.sample()

    def status(self, organization_id: ObjectId) -> dict:
        sessions = [session for session in self.registry.sessions.values()
                    if any(network.organization_id == organization_id
                           for network in session.networks.values())]
        uptime = None if self.started is None else time.monotonic() - self.started
        history = self.traffic_history.get(organization_id, ())
        online = {}
        for session in sessions:
            for network in session.networks.values():
                if network.organization_id != organization_id: continue
                key = network.network_id.__str__()
                online[key] = online.get(key, 0) + 1
        serial = hashlib.sha256(b'serial:' + self.handshake.secret).hexdigest()[:10].upper()
        return dict(
            model=MODEL, firmware=__version__, serial=serial,
            mode='public' if self.public else 'local',
            time=time.strftime('%Y-%m-%d %H:%M:%S'),
            # The operating system's zone: quotas restart on the 1st by this clock.
            timezone=dict(name=time.strftime('%Z'), offset=time.strftime('%z')),
            uptime=None if uptime is None else int(uptime), sessions=len(sessions),
            cpu=self.metrics.get('cpu'), memory=self.metrics.get('memory'),
            memory_percent=self.metrics.get('memory_percent'),
            temperature=self.metrics.get('temperature'),
            traffic=dict(down=[sample[0] for sample in history],
                         up=[sample[1] for sample in history]),
            online=online
        )

    def run_server(self, port: int = 5732):
        self.server.bind((self.ip_address, port))
        self.started = time.monotonic()
        Thread(target=self.save_transfer, daemon=True).start()
        Thread(target=self.collect_metrics, daemon=True).start()
        Thread(target=self.usage.write_forever, daemon=True).start()
        # Own cipher counters and packet order.
        while True:
            delays = [self.bridge_timeout(), self.traffic_delay(), self.egress.next_timeout()]
            timeout = min(delay for delay in delays if delay is not None)
            sources = [self.server, self.waker[0], *self.egress.readers()]
            selected = select.select(sources, self.egress.writers(), self.egress.failures(), timeout)
            readable = selected[0]
            if self.waker[0] in readable: self.waker[0].recv(4096)
            self.egress.ready(*selected)
            self.egress.advance()
            self.forwarding.advance()
            self.firewall.advance()
            self.usage.tick()
            self.advance_bridges()
            self.sample_traffic()
            if self.server not in readable: continue
            connection = self.server.recvfrom(65535)
            self.cleanup_handshakes()
            try: packet_type = Protocol.packet_type(connection[0])
            except ValueError: continue
            if packet_type in (Protocol.client_hello, Protocol.authentication):
                self.receive_handshake(connection)
            elif packet_type == Protocol.data:
                self.send_packet(connection)
            elif packet_type == Protocol.control:
                self.receive_control(connection)


class VPNClient:
    def __init__(self, server_address: Optional[tuple or str] = '192.168.1.0:5732'):
        self.server_address = server_address
        self.speed_monitor = SpeedMonitor()
        if type(self.server_address) == str:
            self.server_address = server_address.split(':')
            self.server_address[1] = int(self.server_address[1])
            self.server_address = tuple(self.server_address)
        # Leave room for the UDP, protocol, counter, and authentication headers.
        self.mtu, self.cipher = 1420, None
        self.networks, self.network_id = [], None
        self.tun, self.interface = None, None
        self.request_id, self.error = 0, None
        self.disconnected, self.kicked = False, False
        self.pending, self.monitoring = b'', False
        self.remembered, self.heard, self.recovering = None, 0, False
        self.connection = [self.server_address[0], '255.255.255.0']
        self.socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Commands from other threads enter the tunnel loop through select().
        self.commands = socket.socketpair()

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
        raise VPNError('server_unreachable')

    def handshake(self) -> ClientHandshake:
        handshake = ClientHandshake()
        handshake.server_hello(self.exchange(handshake.hello()))
        return handshake

    # Code, a CLI and a visual interface use these same calls; every failure
    # they must handle is a VPNError with a stable code (connection.errors).

    def register(self, username: str, email: str, password: str):
        # Creates the account without networks; the password never leaves this computer.
        try:
            handshake = self.handshake()
            handshake.registered(self.exchange(handshake.register(username, email, password)))
        except ValueError: raise VPNError('invalid_server') from None

    def authenticate(self, username: str, password: str = None) -> PacketCipher:
        # The password proves both sides; a wrong one or an impostor fails here.
        # Without a password it logs in again with the stretched value of the last login.
        known = self.remembered[1] if password is None and self.remembered else None
        try:
            handshake = self.handshake()
            login = handshake.login(username, password, known)
            packet = self.exchange(handshake.challenge(self.exchange(login)))
            self.cipher, self.request_id = handshake.configuration(packet), 0
        except LookupError: raise VPNError('incorrect_credentials') from None
        except ValueError: raise VPNError('invalid_server') from None
        self.remembered = username, handshake.srp.stretched
        return self.cipher

    def receive(self, packet: bytes):
        # Data reaches the TUN; control messages return to the caller; False is not from the server.
        try: packet_type = Protocol.packet_type(packet)
        except ValueError: return False
        if packet_type not in (Protocol.data, Protocol.control): return False
        try: content = self.cipher.decrypt(packet, packet_type)
        except (InvalidTag, ValueError): return False
        if packet_type == Protocol.data:
            if self.tun and content:
                self.speed_monitor.update_transfer(self.tun.write(content), 0)
            return None
        try: message = Control.unpack(content)
        except ValueError: return None
        if message.get('action') == Control.disconnected: self.disconnected = True
        if message.get('action') == Control.kicked: self.kicked = True
        return message

    def request(self, action: str, attempts: int = 3, timeout: int = 3,
                **fields) -> dict:
        self.request_id += 1
        message = Control.pack(dict(request=self.request_id, action=action, **fields))
        previous_timeout = self.socket_server.gettimeout()
        try:
            for _ in range(attempts):
                # Each retry needs a fresh counter; the request number stays.
                packet = self.cipher.encrypt(message, Protocol.control)
                self.socket_server.sendto(packet, self.server_address)
                deadline = time.monotonic() + timeout
                while (remaining := deadline - time.monotonic()) > 0:
                    self.socket_server.settimeout(remaining)
                    try: response, address = self.socket_server.recvfrom(65535)
                    except socket.timeout: break
                    if address != self.server_address: continue
                    reply = self.receive(response)
                    if reply and reply.get('request') == self.request_id: return reply
        finally: self.socket_server.settimeout(previous_timeout)
        raise VPNError('server_unreachable')

    def ask(self, action: str, **fields) -> dict:
        # A control request whose refusal becomes a VPNError with the server's code.
        if not self.cipher: raise VPNError('not_authenticated')
        reply = self.request(action, **fields)
        if 'error' in reply: raise VPNError.from_reply(reply)
        return reply

    def create_organization(self, name: str) -> dict:
        # After authenticate: the account founds an organization with a first network.
        reply = self.ask(Control.create_organization, name=name)
        return dict(organization_id=reply['organization_id'], network_id=reply['network_id'])

    def account(self) -> dict:
        # Who is logged in: an interface shows it, and the email others add it by.
        reply = self.ask(Control.account)
        return dict(username=reply.get('username'), email=reply.get('email'))

    def list_networks(self) -> list[dict]:
        # An empty list is not an error: the account waits or founds an organization.
        return self.ask(Control.list_networks).get('networks') or []

    def apply_networks(self, networks: list[dict]):
        # Undo the previous network before the new identity is configured.
        primary = next(network for network in networks if network['primary'])
        if self.networks: remove_networks(self.interface, self.networks, self.server_address[0])
        self.tun.configure(primary['ip_address'], primary['subnet_mask'])
        configure_networks(self.interface, networks, self.server_address[0])
        self.connection = primary['ip_address'], primary['subnet_mask']
        self.networks = networks

    def select_network(self, network_id: str) -> list[dict]:
        reply = self.ask(Control.connect, network_id=network_id)
        networks = Control.networks(reply.get('configuration'))
        if self.tun: self.apply_networks(networks)
        else: self.networks = networks
        self.network_id, self.disconnected = network_id, False
        return networks

    def switch(self, network_id: str):
        # Safe from another thread; the tunnel loop performs the change.
        self.commands[0].send(network_id.encode() + b'\n')

    def stop(self):
        # Safe from another thread: the tunnel ends and removes its routes.
        self.commands[0].send(b'stop\n')

    def status(self) -> dict:
        # What any interface shows while connected; safe from another thread.
        with self.speed_monitor.lock:
            download, upload = self.speed_monitor.speed
            received, sent = self.speed_monitor.transferred
        return dict(connected=bool(self.networks) and not self.recovering, network_id=self.network_id,
                    networks=list(self.networks), recovering=self.recovering,
                    download=download, upload=upload, received=received, sent=sent)

    def commanded(self, data: bytes) -> bool:
        # Returns True when asked to stop; a rejected switch keeps the current network.
        self.pending += data
        *lines, self.pending = self.pending.split(b'\n')
        for line in lines:
            if line == b'stop': return True
            try: self.select_network(line.decode())
            except (UnicodeDecodeError, VPNError) as error: self.error = error
        return False

    def new_tunnel(self, interface: str):
        # Linux and macOS use the kernel's TUN; Windows, the wintun.dll in the executable.
        return devices.open_device(interface, self.mtu)

    def reconnect(self):
        # A notice means the server changed this membership; read it again.
        try: return self.select_network(self.network_id)
        except VPNError as error:
            if error.code == 'server_unreachable': raise
        # A deleted network gives way to the primary one the server chose.
        default = next((network for network in self.list_networks() if network['default']), None)
        if default:
            try: return self.select_network(default['network_id'])
            except VPNError as error:
                if error.code == 'server_unreachable': raise
        raise VPNError('network_lost')

    def connect(self, credentials: tuple = None, interface: str = 'vpn0', network_id: str = None):
        # Without credentials it reuses the session opened by authenticate.
        if credentials: self.authenticate(*credentials)
        networks = self.list_networks()
        if not networks: raise VPNError('no_networks')
        default = next((network for network in networks if network['default']), networks[0])
        # macOS chooses the card's name (utunN): routes use the one it got.
        self.tun = self.new_tunnel(interface)
        self.interface = self.tun.name
        # Whatever ends the tunnel (an error, Ctrl+C, a closed window) removes its routes.
        try: self.tunnel(network_id or default['network_id'])
        finally: self.release()

    def release(self):
        # Addresses and routes of this session leave the computer, once.
        if self.networks and self.interface:
            remove_networks(self.interface, self.networks, self.server_address[0])
        self.networks = []
        if self.tun: self.tun.close()
        self.tun = None

    def tunnel(self, network_id: str):
        self.select_network(network_id)
        if not self.monitoring: self.speed_monitor.start_monitoring()
        self.monitoring, self.heard = True, time.monotonic()
        sources = [self.tun, self.socket_server, self.commands[1]]
        while True:
            for source in select.select(sources, [], [], 1)[0]:
                if source is self.tun:
                    packet = self.cipher.encrypt(source.read(source.mtu))
                    length = self.socket_server.sendto(packet, self.server_address)
                    self.speed_monitor.update_transfer(0, length)
                elif source is self.commands[1]:
                    if self.commanded(source.recv(4096)): return
                else:
                    packet, address = source.recvfrom(65535)
                    if address == self.server_address and self.receive(packet) is not False:
                        self.heard = time.monotonic()
                if self.kicked: raise VPNError('session_ended')
                if self.disconnected: self.reconnect()
            if time.monotonic() - self.heard > self.KEEPALIVE and not self.alive():
                if self.recover(): return

    KEEPALIVE, RETRY = 10, 3

    def alive(self) -> bool:
        # A quiet tunnel asks the server; a restarted one no longer knows this session.
        try: self.request(Control.ping)
        except VPNError: return False
        self.heard = time.monotonic()
        return True

    def recover(self) -> bool:
        # Logs in again with the remembered login and the same network, keeping the card and
        # its routes, until the server answers. Returns True when asked to stop meanwhile.
        if not self.remembered: raise VPNError('server_unreachable')
        self.recovering = True
        try:
            while True:
                try:
                    self.authenticate(self.remembered[0])
                    self.select_network(self.network_id)
                    self.heard = time.monotonic()
                    return False
                except VPNError as error:
                    if error.code != 'server_unreachable': raise
                ready = select.select([self.commands[1]], [], [], self.RETRY)[0]
                if ready and self.commanded(self.commands[1].recv(4096)): return True
        finally: self.recovering = False
