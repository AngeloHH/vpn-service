import socket
import struct
import time

from connection.egress import TCP, UDP

PROTOCOL_NUMBERS = dict(tcp=TCP, udp=UDP)
TCP_IDLE, OTHER_IDLE = 1800, 60
# Conversations remembered so their answers pass; past this, answers face the rules too.
FLOWS = 200_000


def endpoints(packet: bytes):
    # (protocol, source, destination) with ports for TCP and UDP, 0 for the rest.
    if len(packet) < 20 or packet[0] >> 4 != 4: return None
    header, protocol = (packet[0] & 0x0f) * 4, packet[9]
    source, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
    fragment = struct.unpack('!H', packet[6:8])[0] & 0x1fff
    if protocol in (TCP, UDP) and not fragment and len(packet) >= header + 4:
        ports = struct.unpack('!HH', packet[header:header + 4])
    else: ports = 0, 0
    return protocol, (source, ports[0]), (destination, ports[1])


class Firewall:
    """Which members of a network may reach which, as Seguridad defines it.

    Rules are read top to bottom and the first that matches decides. Without
    one, an isolated network refuses and an open one lets the packet through.
    A conversation that was let through is remembered, so its answers pass
    even where a rule would refuse them in that direction.
    """

    def __init__(self):
        # network_id -> dict(isolated, rules); installed whole for each organization.
        self.networks, self.organizations = {}, {}
        self.flows, self.swept = {}, float('-inf')

    def install(self, organization_id, table: dict):
        before = self.organizations.pop(organization_id, set())
        for network_id in before: self.networks.pop(network_id, None)
        self.organizations[organization_id] = set(table)
        self.networks.update(table)
        # New rules apply to conversations already open, from their next packet.
        changed = set(table) | before
        self.flows = {key: last for key, last in self.flows.items() if key[0] not in changed}

    @staticmethod
    def matches(side: dict, session) -> bool:
        if side['kind'] == 'any': return True
        if side['kind'] == 'account': return side['id'] == session.account_id.__str__()
        return session.role_id is not None and side['id'] == session.role_id.__str__()

    def decide(self, network_id, sender, receiver, protocol: int, port: int) -> bool:
        security = self.networks[network_id]
        for rule in security['rules']:
            if rule['protocol'] != 'any' and PROTOCOL_NUMBERS[rule['protocol']] != protocol: continue
            # Other protocols carry port 0, which no rule names.
            if rule['port'] is not None and rule['port'] != port: continue
            if self.matches(rule['source'], sender) and self.matches(rule['destination'], receiver):
                return rule['action'] == 'allow'
        return not security['isolated']

    def allows(self, network_id, sender, receiver, packet: bytes) -> bool:
        # Networks without rules and without isolation never get here past one lookup.
        if network_id not in self.networks: return True
        found = endpoints(packet)
        if not found: return False
        protocol, source, destination = found
        now = time.monotonic()
        if (network_id, protocol, destination, source) in self.flows:
            self.flows[network_id, protocol, destination, source] = now
            return True
        key = network_id, protocol, source, destination
        # A known conversation skips the rules: they were checked when it began.
        if key not in self.flows and not self.decide(network_id, sender, receiver, protocol, destination[1]):
            return False
        if key in self.flows or len(self.flows) < FLOWS: self.flows[key] = now
        return True

    def advance(self, now: float = None):
        # Called on every loop turn; the table is swept once a second.
        now = time.monotonic() if now is None else now
        if now - self.swept < 1: return
        self.swept = now
        self.flows = {key: last for key, last in self.flows.items()
                      if now - last <= (TCP_IDLE if key[1] == TCP else OTHER_IDLE)}
