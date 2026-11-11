import socket
import struct
import time

from connection.egress import TCP, UDP, parse

PROTOCOLS = dict(tcp=(TCP,), udp=(UDP,), both=(TCP, UDP))
# Translated ports, chosen at the panel address of the destination's network.
FIRST_PORT, LAST_PORT = 20000, 60999
UDP_IDLE, TCP_IDLE, TCP_CLOSED = 60, 1800, 10
SESSION_ENTRIES = 256


def fold(total: int) -> int:
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return total


def adjust(value: int, old: bytes, new: bytes) -> int:
    # RFC 1624: the checksum follows the changed words without reading the payload.
    total = ~value & 0xffff
    for (word,) in struct.iter_unpack('!H', old): total += ~word & 0xffff
    for (word,) in struct.iter_unpack('!H', new): total += word
    return ~fold(total) & 0xffff


def rewrite(packet: bytes, header: int, source: tuple, destination: tuple) -> bytes:
    # New addresses and ports; both checksums are corrected, the payload is untouched.
    content = bytearray(packet)
    old_addresses = bytes(content[12:20])
    new_addresses = socket.inet_aton(source[0]) + socket.inet_aton(destination[0])
    old_ports = bytes(content[header:header + 4])
    new_ports = struct.pack('!HH', source[1], destination[1])
    content[12:20], content[header:header + 4] = new_addresses, new_ports
    check = struct.unpack('!H', content[10:12])[0]
    content[10:12] = struct.pack('!H', adjust(check, old_addresses, new_addresses))
    offset = header + (16 if content[9] == TCP else 6)
    check = struct.unpack('!H', content[offset:offset + 2])[0]
    # UDP may leave its checksum out: zero stays zero.
    if content[9] == UDP and not check: return bytes(content)
    check = adjust(check, old_addresses + old_ports, new_addresses + new_ports)
    if content[9] == UDP and not check: check = 0xffff
    content[offset:offset + 2] = struct.pack('!H', check)
    return bytes(content)


class Entry:
    def __init__(self, client, key: tuple, rule: dict, target: tuple, network_id, router: str, port: int):
        self.client, self.key, self.rule = client, key, rule
        # key: (protocol, client address, address it reached); target: where it really goes.
        self.target, self.network_id, self.router, self.port = target, network_id, router, port
        self.last, self.closing = time.monotonic(), False

    @property
    def protocol(self): return self.key[0]

    def expired(self, now: float) -> bool:
        idle = TCP_CLOSED if self.closing else TCP_IDLE if self.protocol == TCP else UDP_IDLE
        return now - self.last > idle


class Forwarding:
    """Addresses of a network that lead somewhere else.

    A rule listens on an address of its network, on one port or on all of them.
    Inside the organization the packet is translated twice: towards the target
    and, so that the answer comes back through the server, from the panel
    address of the target's network. Towards the internet the egress connects
    to the target instead of the address the client used.
    """

    def __init__(self):
        # network_id -> {address: [rule]}; installed whole for each organization.
        self.rules, self.organizations = {}, {}
        self.outgoing, self.incoming, self.cursors = {}, {}, {}
        self.swept = float('-inf')

    # ---------- Rules ----------

    def install(self, organization_id, table: dict):
        # table: network_id -> list of enabled rules, as AccessAdmin.table() builds it.
        for network_id in self.organizations.pop(organization_id, ()): self.rules.pop(network_id, None)
        self.organizations[organization_id] = set(table)
        for network_id, rules in table.items():
            addresses = self.rules[network_id] = {}
            for rule in rules: addresses.setdefault(rule['address'], []).append(rule)
        # Connections keep going only while their rule still says the same.
        current = [rule for rules in table.values() for rule in rules]
        for entry in list(self.outgoing.values()):
            if entry.rule.get('organization_id') == organization_id and not self.same(entry.rule, current):
                self.forget(entry)

    @staticmethod
    def same(rule: dict, current: list) -> bool:
        keys = 'id', 'address', 'port', 'protocol', 'target', 'target_port', 'target_network'
        return any(all(other.get(key) == rule.get(key) for key in keys) for other in current)

    def listens(self, network_id, address: str) -> bool:
        return address in self.rules.get(network_id, {})

    def match(self, network_id, address: str, protocol: int, port: int):
        for rule in self.rules.get(network_id, {}).get(address, ()):
            if protocol not in PROTOCOLS[rule['protocol']]: continue
            if rule['port'] is None or rule['port'] == port: return rule

    def rule_for(self, network_id, packet: bytes):
        details = parse(packet)
        if not details or details[0] not in (TCP, UDP): return None
        return self.match(network_id, details[2][0], details[0], details[2][1])

    @staticmethod
    def destination(rule: dict, port: int) -> tuple:
        # Without its own port the target keeps the one the client used.
        target_port = rule['target_port'] if rule['target_port'] is not None else port
        return rule['target'], target_port

    # ---------- Translation inside the organization ----------

    def free_port(self, network_id, protocol: int):
        start = self.cursors.get(network_id, FIRST_PORT)
        span = LAST_PORT - FIRST_PORT + 1
        for step in range(span):
            port = FIRST_PORT + (start - FIRST_PORT + step) % span
            if (network_id, protocol, port) not in self.incoming:
                # The next search starts after it; the modulo wraps past the last port.
                self.cursors[network_id] = port + 1
                return port

    def outbound(self, client, network_id, packet: bytes, router: str):
        # The client's packet towards the rule's target, from the target network's panel.
        details = parse(packet)
        if not details: return None
        protocol, source, destination, header, flags, total = details
        if protocol not in (TCP, UDP): return None
        rule = self.match(network_id, destination[0], protocol, destination[1])
        if not rule or rule.get('target_network') is None: return None
        key = protocol, source, destination
        entry = self.outgoing.get((client, key))
        if not entry:
            if protocol == TCP and not (flags & 0x02 and not flags & 0x10): return None
            if sum(1 for owner, _ in self.outgoing if owner is client) >= SESSION_ENTRIES: return None
            port = self.free_port(rule['target_network'], protocol)
            if port is None: return None
            target = self.destination(rule, destination[1])
            entry = Entry(client, key, rule, target, rule['target_network'], router, port)
            self.outgoing[client, key] = entry
            self.incoming[rule['target_network'], protocol, port] = entry
        self.touch(entry, flags)
        return entry, rewrite(packet[:total], header, (entry.router, entry.port), entry.target)

    def inbound(self, network_id, packet: bytes):
        # An answer to the panel address of a target network, back to whoever asked.
        details = parse(packet)
        if not details: return None
        protocol, source, destination, header, flags, total = details
        entry = self.incoming.get((network_id, protocol, destination[1]))
        if not entry or destination[0] != entry.router or source != entry.target: return None
        self.touch(entry, flags)
        _, client_address, reached = entry.key
        return entry, rewrite(packet[:total], header, reached, client_address)

    @staticmethod
    def touch(entry: Entry, flags: int):
        entry.last = time.monotonic()
        # A FIN or a reset ends the connection soon; late segments still pass.
        if entry.protocol == TCP and flags & 0x05: entry.closing = True

    def forget(self, entry: Entry):
        self.outgoing.pop((entry.client, entry.key), None)
        if self.incoming.get((entry.network_id, entry.protocol, entry.port)) is entry:
            self.incoming.pop((entry.network_id, entry.protocol, entry.port))

    def advance(self, now: float = None):
        # Called on every loop turn; the table is swept once a second.
        now = time.monotonic() if now is None else now
        if now - self.swept < 1: return
        self.swept = now
        for entry in [entry for entry in self.outgoing.values() if entry.expired(now)]: self.forget(entry)

    def drop(self, session):
        # The session lost its routes: what it opened through a rule ends too.
        for entry in [entry for entry in self.outgoing.values() if entry.client is session]: self.forget(entry)

    @property
    def entries(self) -> int:
        return len(self.outgoing)
