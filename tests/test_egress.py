import select
import socket
import time
import unittest
from unittest import mock

from bson import ObjectId
from scapy.layers.inet import IP, UDP
from tcp_sansio import TCPStack

from connection import egress as module
from connection.database.mongodb import Network
from connection.egress import Egress, public, udp_packet
from connection.protocol import Protocol
from tests.panel import Panel

CLIENT = '10.0.0.5'


class Session:
    # Only identity matters to the egress.
    pass


class Loopback:
    """Real sockets on 127.0.0.1 standing in for servers on the internet."""

    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.accepted = []

    @property
    def udp_port(self): return self.udp.getsockname()[1]

    @property
    def tcp_port(self): return self.listener.getsockname()[1]

    def echo_udp(self):
        while select.select([self.udp], [], [], 0)[0]:
            content, address = self.udp.recvfrom(65535)
            self.udp.sendto(content.upper(), address)

    def accept(self):
        try: connection, _ = self.listener.accept()
        except BlockingIOError: return
        connection.setblocking(False)
        self.accepted.append(connection)

    def close(self):
        for sock in [self.udp, self.listener, *self.accepted]: sock.close()


class EgressTest(unittest.TestCase):
    def setUp(self):
        self.delivered = []
        self.egress = Egress(lambda session, packet: self.delivered.append((session, packet)),
                             allowed=lambda address: True)
        self.session, self.remote = Session(), Loopback()
        self.client = TCPStack(CLIENT, seed=1)

    def tearDown(self):
        self.egress.drop(self.session)
        self.remote.close()

    def turn(self, rounds=1):
        # One iteration of the server loop, plus the client and the remote side.
        for _ in range(rounds):
            for packet in self.client.transmit(): self.egress.outbound(self.session, packet)
            readers, writers, failures = self.egress.readers(), self.egress.writers(), self.egress.failures()
            selected = select.select(readers, writers, failures, 0.01) if readers or writers or failures else ([], [], [])
            self.egress.ready(*selected)
            self.egress.advance()
            self.remote.echo_udp(), self.remote.accept()
            for session, packet in self.delivered:
                self.assertIs(session, self.session)
                if IP(packet).proto == 6: self.client.receive(packet)
            self.delivered = [item for item in self.delivered if IP(item[1]).proto != 6]

    def until(self, condition, rounds=300):
        for _ in range(rounds):
            if condition(): return
            self.turn()
        self.fail('the condition was never met')

    def udp(self, port, payload, source_port=40000):
        return bytes(IP(src=CLIENT, dst='127.0.0.1') / UDP(sport=source_port, dport=port) / payload)

    def test_only_public_addresses_leave(self):
        for address in ('8.8.8.8', '1.1.1.1', '93.184.216.34'): self.assertTrue(public(address))
        for address in ('127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254',
                        '100.64.0.1', '172.16.0.1', '0.0.0.0', '224.0.0.1'):
            self.assertFalse(public(address))
        closed = Egress(lambda *_: None)
        self.assertFalse(closed.outbound(self.session, self.udp(53, b'x')))
        self.assertEqual(closed.flows, 0)

    def test_replies_are_valid_udp_packets(self):
        packet = udp_packet(('8.8.8.8', 53), (CLIENT, 40000), b'answer')
        parsed = IP(packet)
        self.assertEqual((parsed.src, parsed.dst, parsed[UDP].sport, parsed[UDP].dport, bytes(parsed[UDP].payload)),
                         ('8.8.8.8', CLIENT, 53, 40000, b'answer'))
        rebuilt = IP(packet)
        del rebuilt.chksum, rebuilt[UDP].chksum
        self.assertEqual(bytes(rebuilt), packet)

    def test_udp_goes_out_and_comes_back(self):
        self.assertTrue(self.egress.outbound(self.session, self.udp(self.remote.udp_port, b'hello')))
        self.until(lambda: self.delivered)
        reply = IP(self.delivered[0][1])
        self.assertEqual((reply.src, reply[UDP].sport, reply.dst, reply[UDP].dport),
                         ('127.0.0.1', self.remote.udp_port, CLIENT, 40000))
        self.assertEqual(bytes(reply[UDP].payload), b'HELLO')
        # The same flow reuses its socket.
        self.egress.outbound(self.session, self.udp(self.remote.udp_port, b'again'))
        self.assertEqual(self.egress.flows, 1)

    def test_idle_udp_flows_close(self):
        self.egress.outbound(self.session, self.udp(self.remote.udp_port, b'x'))
        with mock.patch.object(module, 'UDP_IDLE', -1): self.egress.advance()
        self.assertEqual(self.egress.flows, 0)

    def test_tcp_is_relayed_after_the_destination_accepts(self):
        connection = self.client.connect('127.0.0.1', self.remote.tcp_port, 50000)
        self.turn()
        # The SYN is held: the client is not answered before the destination is.
        self.until(lambda: self.remote.accepted)
        self.until(lambda: connection.state == 'ESTABLISHED')
        remote = self.remote.accepted[0]

        connection.send(b'request')
        received = b''

        def remote_received():
            nonlocal received
            try: received += remote.recv(65535)
            except BlockingIOError: pass
            return received == b'request'
        self.until(remote_received)

        payload = bytes(range(256)) * 4096
        remote.setblocking(True)
        remote.sendall(payload)
        remote.close()
        self.remote.accepted.remove(remote)
        collected = b''

        def client_received():
            nonlocal collected
            collected += connection.receive()
            return connection.eof
        self.until(client_received, 3000)
        self.assertEqual(collected, payload)
        connection.close()
        self.until(lambda: self.egress.flows == 0)

    def test_a_retransmitted_syn_opens_one_connection(self):
        connection = self.client.connect('127.0.0.1', self.remote.tcp_port, 50000)
        syn = self.client.transmit()[0]
        self.egress.outbound(self.session, syn)
        self.egress.outbound(self.session, syn)
        self.assertEqual(self.egress.flows, 1)
        self.until(lambda: connection.state == 'ESTABLISHED')
        self.assertEqual(len(self.remote.accepted), 1)

    def test_a_refused_destination_resets_the_client(self):
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        port = closed.getsockname()[1]
        closed.close()
        connection = self.client.connect('127.0.0.1', port, 50000)
        states = []
        self.until(lambda: states.append(connection.state) or connection.state == 'CLOSED')
        # The client was never told the connection existed.
        self.assertNotIn('ESTABLISHED', states)
        self.assertEqual(self.egress.flows, 0)

    def test_a_slow_side_stops_reading_the_other(self):
        connection = self.client.connect('127.0.0.1', self.remote.tcp_port, 50000)
        self.until(lambda: connection.state == 'ESTABLISHED' and self.remote.accepted)
        remote = self.remote.accepted[0]
        relay = next(iter(next(iter(self.egress.sessions.values())).relays.values()))
        # The client reads nothing: the relay holds one chunk at most, not the whole stream.
        payload = bytes(range(256)) * 32768
        sent = 0
        for _ in range(300):
            try: sent += remote.send(payload[sent:sent + 65536])
            except BlockingIOError: pass
            self.turn()
            self.assertLessEqual(len(relay.downstream), module.CHUNK)
        # The destination reads nothing either: the client's bytes are kept, not replaced.
        upload = bytes(reversed(range(256))) * 32768
        written = 0
        for _ in range(300):
            written += connection.send(upload[written:])
            self.turn()
        received, collected = b'', b''
        remote.setblocking(False)

        def drained():
            nonlocal received, collected
            try: received += remote.recv(1 << 20)
            except BlockingIOError: pass
            collected += connection.receive()
            return len(received) == written and len(collected) == sent
        for _ in range(3000):
            if drained(): break
            try: sent += remote.send(payload[sent:sent + 65536]) if sent < len(payload) else 0
            except BlockingIOError: pass
            if written < len(upload): written += connection.send(upload[written:])
            self.turn()
        self.assertEqual(received, upload[:written])
        self.assertEqual(collected, payload[:sent])
        self.assertGreater(written, 1 << 20)

    def test_fragments_and_truncated_packets_are_not_forwarded(self):
        fragment = IP(src=CLIENT, dst='127.0.0.1', flags='MF') / UDP(sport=40000, dport=self.remote.udp_port) / b'x'
        self.assertFalse(self.egress.outbound(self.session, bytes(fragment)))
        truncated = self.udp(self.remote.udp_port, b'payload')[:-3]
        self.assertFalse(self.egress.outbound(self.session, truncated))
        self.assertEqual(self.egress.flows, 0)

    def test_flows_per_session_are_limited(self):
        with mock.patch.object(module, 'SESSION_FLOWS', 1):
            self.assertTrue(self.egress.outbound(self.session, self.udp(self.remote.udp_port, b'a', 40000)))
            self.assertFalse(self.egress.outbound(self.session, self.udp(self.remote.udp_port, b'b', 40001)))
            connection = self.client.connect('127.0.0.1', self.remote.tcp_port, 50000)
            self.until(lambda: connection.state == 'CLOSED')
        self.assertEqual(self.egress.flows, 1)

    def test_dropping_the_session_resets_its_connections(self):
        connection = self.client.connect('127.0.0.1', self.remote.tcp_port, 50000)
        self.until(lambda: connection.state == 'ESTABLISHED')
        self.egress.outbound(self.session, self.udp(self.remote.udp_port, b'x'))
        self.egress.drop(self.session)
        self.assertEqual(self.egress.flows, 0)
        for _, packet in self.delivered: self.client.receive(packet)
        self.assertEqual(connection.state, 'CLOSED')


class EgressTunnelTest(Panel, unittest.TestCase):
    address = ('127.0.0.1', 53000)

    def setUp(self):
        super().setUp()
        self.remote = Loopback()
        self.server.internet, self.server.egress.allowed = True, lambda address: True
        self.replies = []

    def tearDown(self):
        self.remote.close()
        super().tearDown() if hasattr(super(), 'tearDown') else None

    def send(self, cipher, packet):
        self.server.send_packet((cipher.encrypt(packet), self.address))

    def collect(self, cipher):
        for _ in range(100):
            selected = select.select(self.server.egress.readers(), [], [], 0.01)
            self.server.egress.ready(selected[0], [], [])
            self.remote.echo_udp()
            while self.server.server.packets:
                packet, _ = self.server.server.packets.pop(0)
                if Protocol.packet_type(packet) == Protocol.data: self.replies.append(IP(cipher.decrypt(packet)))
            if self.replies: return

    def udp(self, ip_address, payload, destination='127.0.0.1'):
        return bytes(IP(src=ip_address, dst=destination) / UDP(sport=40000, dport=self.remote.udp_port) / payload)

    def test_a_network_with_internet_lets_traffic_out(self):
        Network(self.collections['networks'], self.network_id).update(internet=True)
        cipher, ip_address = self.vpn('owner', self.address)
        self.send(cipher, self.udp(ip_address, b'ping'))
        self.collect(cipher)
        self.assertEqual([(reply.src, reply.dst, bytes(reply[UDP].payload)) for reply in self.replies],
                         [('127.0.0.1', ip_address, b'PING')])
        # Losing the routes ends its flows.
        self.server.disconnect(self.owner)
        self.assertEqual(self.server.egress.flows, 0)

    def test_without_internet_nothing_leaves(self):
        cipher, ip_address = self.vpn('owner', self.address)
        self.send(cipher, self.udp(ip_address, b'ping'))
        self.assertEqual(self.server.egress.flows, 0)

    def test_the_server_switch_comes_first(self):
        # The network allows it, but the server was started without --internet.
        self.server.internet = False
        Network(self.collections['networks'], self.network_id).update(internet=True)
        cipher, ip_address = self.vpn('owner', self.address)
        self.assertFalse(self.server.registry.get_account(self.owner).internet)
        self.send(cipher, self.udp(ip_address, b'ping'))
        self.assertEqual(self.server.egress.flows, 0)

    def test_own_networks_never_leave(self):
        Network(self.collections['networks'], self.network_id).update(internet=True)
        cipher, ip_address = self.vpn('owner', self.address)
        # 10.0.0.9 belongs to the network even with nobody there.
        self.send(cipher, self.udp(ip_address, b'ping', '10.0.0.9'))
        self.assertEqual(self.server.egress.flows, 0)


if __name__ == '__main__':
    unittest.main()
