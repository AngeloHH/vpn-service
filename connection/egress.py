import platform
import socket
import struct
import time
from ipaddress import ip_address as parse_address

from tcp_sansio import AddressInUseError, PacketError, TCPStack, TCPStateError

TCP, UDP = 6, 17
UDP_IDLE, CONNECT_TIMEOUT = 60, 10
CHUNK = 65536
# Sockets per session, and for the whole server: select() on Windows stops at 512.
SESSION_FLOWS = 256
SERVER_SOCKETS = 450 if platform.system() == 'Windows' else 4000
# The egress stack answers as every destination; its own address is never one.
STACK_ADDRESS = '192.0.2.1'


def public(address: str) -> bool:
    # Loopback, private, link-local and the like stay unreachable: they are the server's.
    # Multicast counts as global for Python, but it is not one destination.
    address = parse_address(address)
    return address.is_global and not address.is_multicast


def checksum(content: bytes) -> int:
    if len(content) % 2: content += b'\0'
    total = sum(struct.unpack(f'!{len(content) // 2}H', content))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def udp_packet(source: tuple, destination: tuple, payload: bytes) -> bytes:
    # The reply the client expects: from the destination back to its own port.
    addresses = socket.inet_aton(source[0]) + socket.inet_aton(destination[0])
    length = 8 + len(payload)
    header = struct.pack('!HHHH', source[1], destination[1], length, 0)
    pseudo = addresses + struct.pack('!BBH', 0, UDP, length)
    value = checksum(pseudo + header + payload) or 0xffff
    header = header[:6] + struct.pack('!H', value)
    ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + length, 0, 0x4000, 64, UDP, 0) + addresses
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return ip + header + payload


def parse(packet: bytes):
    # (protocol, source, destination, header length, flags) of an unfragmented IPv4 packet.
    if len(packet) < 20 or packet[0] >> 4 != 4: return None
    header = (packet[0] & 0x0f) * 4
    total = struct.unpack('!H', packet[2:4])[0]
    fragment = struct.unpack('!H', packet[6:8])[0]
    if header < 20 or total > len(packet) or fragment & 0x3fff: return None
    protocol = packet[9]
    if len(packet) < header + (20 if protocol == TCP else 8): return None
    source_port, destination_port = struct.unpack('!HH', packet[header:header + 4])
    source = socket.inet_ntoa(packet[12:16]), source_port
    destination = socket.inet_ntoa(packet[16:20]), destination_port
    flags = packet[header + 13] if protocol == TCP else 0
    return protocol, source, destination, header, flags, total


class UDPFlow:
    def __init__(self, owner, key: tuple, real: tuple = None):
        self.owner, self.key, self.last = owner, key, time.monotonic()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        # Connected: only the destination's replies reach this client.
        # A forwarding rule sends it elsewhere; the replies keep the address the client used.
        self.socket.connect(real or key[1])

    def send(self, payload: bytes):
        self.last = time.monotonic()
        try: self.socket.send(payload)
        except OSError: pass

    def readable(self):
        try: payload = self.socket.recv(CHUNK)
        except OSError: return
        self.last = time.monotonic()
        self.owner.deliver(udp_packet(self.key[1], self.key[0], payload))

    def close(self):
        self.socket.close()


class PendingTCP:
    # A SYN waits here until the real destination accepts the connection.
    def __init__(self, owner, key: tuple, syn: bytes, real: tuple = None):
        self.owner, self.key, self.syn = owner, key, syn
        self.deadline = time.monotonic() + CONNECT_TIMEOUT
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(False)
        self.socket.connect_ex(real or key[1])

    def connected(self) -> bool:
        return self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0

    def close(self):
        self.socket.close()


class TCPRelay:
    # Copies bytes both ways; a full side stops reading the other one.
    def __init__(self, owner, key: tuple, connection, sock: socket.socket):
        self.owner, self.key = owner, key
        self.connection, self.socket = connection, sock
        self.upstream, self.downstream = b'', b''
        self.client_done = self.server_done = self.closed = False

    @property
    def wants_read(self) -> bool:
        return not self.downstream and not self.server_done

    @property
    def wants_write(self) -> bool:
        return bool(self.upstream)

    def from_client(self):
        # Unread data stays in the stack, whose window then slows the client.
        if self.upstream or self.closed: return
        try: self.upstream = self.connection.receive(CHUNK)
        except (KeyError, TCPStateError): return self.close(reset=True)
        self.to_server()

    def to_server(self):
        if self.upstream:
            try: sent = self.socket.send(self.upstream)
            except BlockingIOError: sent = 0
            except OSError: return self.close(reset=True)
            self.upstream = self.upstream[sent:]
        # The client finished sending; the destination may still answer.
        if not self.upstream and self.client_done and not self.closed:
            try: self.socket.shutdown(socket.SHUT_WR)
            except OSError: pass

    def from_server(self):
        try: content = self.socket.recv(CHUNK)
        except BlockingIOError: return
        except OSError: return self.close(reset=True)
        if not content: self.server_done = True
        self.downstream += content
        self.to_client()

    def to_client(self):
        if self.downstream:
            try: sent = self.connection.send(self.downstream)
            except (KeyError, TCPStateError): return self.close(reset=True)
            self.downstream = self.downstream[sent:]
        # The destination finished: the client gets a FIN and the relay ends.
        if not self.downstream and self.server_done:
            try: self.connection.close()
            except (KeyError, TCPStateError): pass
            self.close()

    def client_eof(self):
        self.client_done = True
        # A reset from the client ends both sides at once.
        if self.connection.state == 'CLOSED': return self.close(reset=True)
        self.from_client()
        self.to_server()

    def close(self, reset: bool = False):
        if self.closed: return
        self.closed = True
        if reset:
            try: self.connection.abort()
            except (KeyError, TCPStateError): pass
        # A closed connection keeps delivering its queued bytes after release.
        self.connection.release()
        self.socket.close()
        self.owner.forget(self)


class SessionEgress:
    def __init__(self, egress, session):
        self.egress, self.session = egress, session
        self.udp, self.pending, self.relays = {}, {}, {}
        self.stack, self.warned = None, float('-inf')

    @property
    def count(self) -> int:
        return len(self.udp) + len(self.pending) + len(self.relays)

    def deliver(self, packet: bytes):
        self.egress.deliver(self.session, packet)

    def tcp_stack(self) -> TCPStack:
        if not self.stack: self.stack = TCPStack(STACK_ADDRESS, any_ip=True)
        return self.stack

    def flush(self):
        if not self.stack: return
        for packet in self.stack.transmit(): self.deliver(packet)

    def refuse(self, packet: bytes):
        # Without an intercepted connection the stack answers with a reset.
        try: self.tcp_stack().receive(packet)
        except PacketError: return
        self.flush()

    def forget(self, item):
        for table in (self.udp, self.pending, self.relays):
            if table.get(item.key) is item: table.pop(item.key)
        self.egress.unregister(item.socket)

    def close(self):
        for relay in list(self.relays.values()): relay.close(reset=True)
        for item in list(self.udp.values()) + list(self.pending.values()):
            self.egress.unregister(item.socket)
            item.close()
        self.udp.clear(), self.pending.clear()
        if self.stack:
            for packet in self.stack.close(): self.deliver(packet)
            self.stack = None


class Egress:
    """The way out to the internet for sessions whose network allows it.

    Every socket is non-blocking and is watched by the server's own select()
    loop: no thread is started per packet or per connection.
    """

    def __init__(self, deliver, allowed=public, notify=None):
        self.deliver, self.allowed, self.notify = deliver, allowed, notify
        self.sessions, self.sockets = {}, {}

    # ---------- Packets from clients ----------

    def outbound(self, session, packet: bytes, target=None) -> bool:
        # target(destination) -> (address, port): where a forwarding rule really leads.
        details = parse(packet)
        if not details: return False
        protocol, source, destination, header, flags, total = details
        if protocol not in (TCP, UDP): return False
        real = target(protocol, destination) if target else None
        if target and not real: return False
        if not self.allowed((real or destination)[0]): return False
        owner = self.sessions.get(session) or self.sessions.setdefault(session, SessionEgress(self, session))
        key = source, destination
        if protocol == UDP: return self.udp_out(owner, key, packet[header + 8:total], real)
        return self.tcp_out(owner, key, packet[:total], flags, real)

    def room(self, owner) -> bool:
        if owner.count < SESSION_FLOWS and len(self.sockets) < SERVER_SOCKETS: return True
        # Reported once a minute per session, not once per refused packet.
        now = time.monotonic()
        if self.notify and now - owner.warned > 60:
            owner.warned = now
            self.notify(owner.session, 'internet_limit')
        return False

    def udp_out(self, owner, key: tuple, payload: bytes, real: tuple = None) -> bool:
        flow = owner.udp.get(key)
        if not flow:
            if not self.room(owner): return False
            try: flow = UDPFlow(owner, key, real)
            except OSError: return False
            owner.udp[key] = flow
            self.sockets[flow.socket] = flow
        flow.send(payload)
        return True

    def tcp_out(self, owner, key: tuple, packet: bytes, flags: int, real: tuple = None) -> bool:
        syn = flags & 0x02 and not flags & 0x10
        if key in owner.relays or not syn:
            # Traffic of a known connection, or a stray segment the stack resets.
            try: owner.tcp_stack().receive(packet)
            except PacketError: return False
            self.service(owner)
            return True
        # A retransmitted SYN waits with the first one, which is identical.
        if key in owner.pending: return True
        if not self.room(owner): owner.refuse(packet)
        else:
            try: pending = PendingTCP(owner, key, packet, real)
            except OSError: owner.refuse(packet)
            else:
                owner.pending[key] = pending
                self.sockets[pending.socket] = pending
        return True

    # ---------- The select() loop ----------

    def readers(self) -> list:
        return [sock for sock, item in self.sockets.items()
                if isinstance(item, UDPFlow) or (isinstance(item, TCPRelay) and item.wants_read)]

    def writers(self) -> list:
        return [sock for sock, item in self.sockets.items()
                if isinstance(item, PendingTCP) or (isinstance(item, TCPRelay) and item.wants_write)]

    def failures(self) -> list:
        # Windows reports a refused connect() here instead of as writable.
        return [sock for sock, item in self.sockets.items() if isinstance(item, PendingTCP)]

    def ready(self, readable, writable, failed):
        for sock in set(readable) | set(writable) | set(failed):
            item = self.sockets.get(sock)
            if isinstance(item, UDPFlow) and sock in readable: item.readable()
            elif isinstance(item, PendingTCP): self.established(item, sock in failed)
            elif isinstance(item, TCPRelay):
                if sock in writable: item.to_server(), item.from_client()
                if sock in readable and not item.closed: item.from_server()
                self.service(item.owner)

    def established(self, pending: PendingTCP, failed: bool):
        owner = pending.owner
        owner.pending.pop(pending.key, None)
        self.unregister(pending.socket)
        if failed or not pending.connected():
            pending.close()
            return owner.refuse(pending.syn)
        try: connection = owner.tcp_stack().intercept(pending.syn)
        except (PacketError, AddressInUseError):
            pending.close()
            return
        relay = TCPRelay(owner, pending.key, connection, pending.socket)
        owner.relays[pending.key] = relay
        self.sockets[pending.socket] = relay
        self.service(owner)

    def service(self, owner):
        # Moves data the stack accepted or can take, then sends its packets.
        if not owner.stack: return
        relays = {relay.connection.id: relay for relay in owner.relays.values()}
        for event in owner.stack.events():
            relay = relays.get(event.connection.id)
            if not relay or relay.closed: continue
            if event.readable: relay.from_client()
            if event.writable: relay.to_client()
            if event.eof: relay.client_eof()
        owner.flush()

    def advance(self):
        # Timers: stack retransmissions, idle UDP flows and slow destinations.
        now = time.monotonic()
        for owner in list(self.sessions.values()):
            for flow in [flow for flow in owner.udp.values() if now - flow.last > UDP_IDLE]:
                owner.forget(flow)
                flow.close()
            for pending in [item for item in owner.pending.values() if now > item.deadline]:
                self.established(pending, True)
            if owner.stack:
                owner.stack.advance()
                self.service(owner)
            if not owner.count and not owner.stack: self.sessions.pop(owner.session, None)

    def next_timeout(self):
        delays = [1.0] if any(owner.udp or owner.pending for owner in self.sessions.values()) else []
        for owner in self.sessions.values():
            if not owner.stack: continue
            delay = owner.stack.next_timeout()
            if delay is not None: delays.append(delay)
        return min(delays) if delays else None

    def unregister(self, sock):
        self.sockets.pop(sock, None)

    def drop(self, session):
        # The session lost its routes: its connections to the internet end too.
        owner = self.sessions.pop(session, None)
        if owner: owner.close()

    @property
    def flows(self) -> int:
        return len(self.sockets)
