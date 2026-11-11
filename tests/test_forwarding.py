import select
import time
import unittest
from unittest import mock

from bson import ObjectId
from scapy.layers.inet import IP, TCP as TCPHeader, UDP
from tcp_sansio import TCPStack

from connection import forwarding as module
from connection.database.mongodb import Network
from connection.forwarding import Forwarding, rewrite
from connection.network_admin import NetworkError
from connection.protocol import Protocol
from tests.panel import Panel
from tests.test_egress import Loopback

NETWORK, OTHER = ObjectId(), ObjectId()


def rule(**fields):
    values = dict(id='r1', organization_id='org', address='10.0.0.50', port=7000, protocol='udp',
                  target='10.1.0.1', target_port=None, target_network=OTHER, enabled=True)
    values.update(fields)
    return values


def udp(source, destination, payload=b'hello', checksum=None):
    packet = IP(src=source[0], dst=destination[0]) / UDP(sport=source[1], dport=destination[1]) / payload
    if checksum is not None: packet[UDP].chksum = checksum
    return bytes(packet)


def tcp(source, destination, flags='S'):
    return bytes(IP(src=source[0], dst=destination[0]) / TCPHeader(sport=source[1], dport=destination[1], flags=flags))


def valid(packet: bytes) -> bool:
    # scapy recomputes both checksums when they are deleted.
    parsed = IP(packet)
    layer = parsed[UDP] if parsed.proto == 17 else parsed[TCPHeader]
    del parsed.chksum, layer.chksum
    return bytes(parsed) == packet


class Client:
    # Only identity matters to the translation table.
    pass


class ForwardingTest(unittest.TestCase):
    def setUp(self):
        self.forwarding, self.client = Forwarding(), Client()
        self.forwarding.install('org', {NETWORK: [rule()]})

    def out(self, packet, client=None):
        return self.forwarding.outbound(client or self.client, NETWORK, packet, '10.1.0.254')

    def test_rewritten_packets_keep_valid_checksums(self):
        for packet in (udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)), tcp(('10.0.0.1', 40000), ('10.0.0.50', 80)),
                       udp(('10.0.0.1', 40000), ('10.0.0.50', 7000), b'odd')):
            header = (packet[0] & 0x0f) * 4
            changed = rewrite(packet, header, ('10.1.0.254', 20000), ('10.1.0.1', 65535))
            parsed = IP(changed)
            self.assertEqual((parsed.src, parsed.dst, parsed.sport, parsed.dport), ('10.1.0.254', '10.1.0.1', 20000, 65535))
            self.assertTrue(valid(changed))
        # A UDP packet without a checksum keeps going without one.
        packet = udp(('10.0.0.1', 40000), ('10.0.0.50', 7000), checksum=0)
        self.assertEqual(IP(rewrite(packet, 20, ('1.1.1.1', 1), ('2.2.2.2', 2)))[UDP].chksum, 0)

    def test_a_checksum_that_turns_zero_is_written_as_ones(self):
        # 0 means "no checksum" in UDP; the same value is sent as 0xffff.
        self.assertEqual(module.adjust(0xffff, b'\x00\x00', b'\x00\x00'), 0)
        packet = udp(('10.0.0.1', 40000), ('10.0.0.50', 7000))
        for port in range(1, 65536):
            changed = rewrite(packet, 20, ('10.1.0.254', port), ('10.1.0.1', 7000))
            if IP(changed)[UDP].chksum == 0xffff: break
        else: self.fail('no port gave a zero checksum')
        self.assertTrue(valid(changed) or IP(changed)[UDP].chksum == 0xffff)

    def test_rules_match_their_protocol_and_port(self):
        self.forwarding.install('org', {NETWORK: [rule(), rule(id='r2', address='10.0.0.60', port=None, protocol='both')]})
        self.assertIsNotNone(self.forwarding.match(NETWORK, '10.0.0.50', 17, 7000))
        self.assertIsNone(self.forwarding.match(NETWORK, '10.0.0.50', 17, 7001))
        self.assertIsNone(self.forwarding.match(NETWORK, '10.0.0.50', 6, 7000))
        self.assertEqual(self.forwarding.match(NETWORK, '10.0.0.60', 6, 1)['id'], 'r2')
        self.assertIsNone(self.forwarding.match(OTHER, '10.0.0.50', 17, 7000))
        self.assertEqual(self.forwarding.destination(rule(target_port=9), 7000), ('10.1.0.1', 9))
        self.assertEqual(self.forwarding.destination(rule(), 7000), ('10.1.0.1', 7000))

    def test_both_directions_are_translated(self):
        entry, packet = self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))
        parsed = IP(packet)
        self.assertEqual((parsed.src, parsed.sport, parsed.dst, parsed.dport), ('10.1.0.254', 20000, '10.1.0.1', 7000))
        # The same flow keeps its port.
        self.assertIs(self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))[0], entry)
        back = self.forwarding.inbound(OTHER, udp(('10.1.0.1', 7000), ('10.1.0.254', 20000), b'answer'))
        self.assertIs(back[0].client, self.client)
        parsed = IP(back[1])
        self.assertEqual((parsed.src, parsed.sport, parsed.dst, parsed.dport), ('10.0.0.50', 7000, '10.0.0.1', 40000))
        self.assertTrue(valid(back[1]))

    def test_answers_from_anyone_else_are_ignored(self):
        self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))
        for packet in (udp(('10.1.0.9', 7000), ('10.1.0.254', 20000)), udp(('10.1.0.1', 7001), ('10.1.0.254', 20000)),
                       udp(('10.1.0.1', 7000), ('10.1.0.253', 20000)), udp(('10.1.0.1', 7000), ('10.1.0.254', 20001))):
            self.assertIsNone(self.forwarding.inbound(OTHER, packet))
        self.assertIsNone(self.forwarding.inbound(NETWORK, udp(('10.1.0.1', 7000), ('10.1.0.254', 20000))))

    def test_ports_are_not_shared_and_wrap_around(self):
        first = self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))[0]
        second = self.out(udp(('10.0.0.2', 40000), ('10.0.0.50', 7000)))[0]
        self.assertEqual((first.port, second.port), (20000, 20001))
        self.forwarding.cursors[OTHER] = module.LAST_PORT
        self.assertEqual(self.out(udp(('10.0.0.3', 40000), ('10.0.0.50', 7000)))[0].port, module.LAST_PORT)
        self.assertEqual(self.out(udp(('10.0.0.4', 40000), ('10.0.0.50', 7000)))[0].port, 20002)
        with mock.patch.object(module, 'LAST_PORT', 20002):
            self.assertIsNone(self.forwarding.free_port(OTHER, 17))
            self.assertEqual(self.forwarding.free_port(OTHER, 6), 20000)

    def test_tcp_opens_only_with_a_syn(self):
        self.forwarding.install('org', {NETWORK: [rule(protocol='tcp', port=80)]})
        self.assertIsNone(self.out(tcp(('10.0.0.1', 40000), ('10.0.0.50', 80), 'A')))
        self.assertIsNone(self.out(tcp(('10.0.0.1', 40000), ('10.0.0.50', 80), 'SA')))
        entry, _ = self.out(tcp(('10.0.0.1', 40000), ('10.0.0.50', 80)))
        self.assertIsNotNone(self.out(tcp(('10.0.0.1', 40000), ('10.0.0.50', 80), 'A')))
        self.assertFalse(entry.closing)
        self.out(tcp(('10.0.0.1', 40000), ('10.0.0.50', 80), 'FA'))
        self.assertTrue(entry.closing)

    def test_internet_rules_and_other_packets_are_not_translated(self):
        self.forwarding.install('org', {NETWORK: [rule(target_network=None, target='8.8.8.8')]})
        self.assertIsNone(self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000))))
        self.assertIsNone(self.out(bytes(IP(src='10.0.0.1', dst='10.0.0.50') / b'raw')))
        self.assertIsNone(self.out(b'short'))
        self.assertIsNone(self.forwarding.inbound(OTHER, b'short'))
        self.assertIsNone(self.forwarding.rule_for(NETWORK, bytes(IP(src='10.0.0.1', dst='10.0.0.50', proto=1) / b'raw')))

    def test_entries_expire_by_protocol(self):
        udp_entry = self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))[0]
        now = time.monotonic()
        self.assertFalse(udp_entry.expired(now + module.UDP_IDLE - 1))
        self.assertTrue(udp_entry.expired(now + module.UDP_IDLE + 1))
        self.forwarding.install('org', {NETWORK: [rule(protocol='tcp', port=80)]})
        tcp_entry = self.out(tcp(('10.0.0.1', 40000), ('10.0.0.50', 80)))[0]
        self.assertFalse(tcp_entry.expired(now + module.UDP_IDLE + 1))
        self.assertTrue(tcp_entry.expired(now + module.TCP_IDLE + 1))
        tcp_entry.closing = True
        self.assertTrue(tcp_entry.expired(now + module.TCP_CLOSED + 1))

    def test_the_table_is_swept_once_a_second(self):
        entry = self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))[0]
        later = time.monotonic() + module.UDP_IDLE + 5
        entry.last = later - module.UDP_IDLE + 1
        self.forwarding.advance(later)
        self.assertEqual(self.forwarding.entries, 1)
        entry.last = 0
        self.forwarding.advance(later + 0.5)
        self.assertEqual(self.forwarding.entries, 1)
        self.forwarding.advance(later + 1)
        self.assertEqual((self.forwarding.entries, self.forwarding.incoming), (0, {}))

    def test_a_session_has_a_limited_number_of_entries(self):
        with mock.patch.object(module, 'SESSION_ENTRIES', 2):
            for port in (1, 2): self.assertIsNotNone(self.out(udp(('10.0.0.1', port), ('10.0.0.50', 7000))))
            self.assertIsNone(self.out(udp(('10.0.0.1', 3), ('10.0.0.50', 7000))))
            self.assertIsNotNone(self.out(udp(('10.0.0.2', 3), ('10.0.0.50', 7000)), Client()))

    def test_dropping_a_session_ends_its_entries(self):
        self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))
        other = Client()
        self.out(udp(('10.0.0.2', 40000), ('10.0.0.50', 7000)), other)
        self.forwarding.drop(self.client)
        self.assertEqual([entry.client for entry in self.forwarding.outgoing.values()], [other])
        self.assertEqual(len(self.forwarding.incoming), 1)

    def test_a_changed_rule_ends_its_connections(self):
        self.out(udp(('10.0.0.1', 40000), ('10.0.0.50', 7000)))
        self.forwarding.install('org', {NETWORK: [rule(name='renamed')]})
        self.assertEqual(self.forwarding.entries, 1)
        self.forwarding.install('another', {})
        self.assertEqual(self.forwarding.entries, 1)
        self.forwarding.install('org', {NETWORK: [rule(target='10.1.0.2')]})
        self.assertEqual(self.forwarding.entries, 0)
        self.assertTrue(self.forwarding.listens(NETWORK, '10.0.0.50'))
        self.forwarding.install('org', {})
        self.assertFalse(self.forwarding.listens(NETWORK, '10.0.0.50'))


class AccessTest(Panel, unittest.TestCase):
    owner_address, guest_address = ('127.0.0.1', 51000), ('127.0.0.1', 51001)

    def setUp(self):
        super().setUp()
        self.admin = self.server.access_admin
        network = Network(self.collections['networks'])
        network.create('10.1.0.0/24', 253, self.organization, 'Oficina')
        self.other = network.id
        self.guest = self.account('guest')
        self.organizations.join(self.guest, self.organization, self.other)
        self.server.add_virtual_http(self.other)

    def apply(self, effects):
        self.server.complete_change(dict(effects, organization_id=self.organization))
        return effects

    def forward(self, **body):
        values = dict(address='10.0.0.50', port=7000, protocol='udp', target='10.1.0.1', target_port=None)
        values.update(body)
        return self.apply(self.admin.add_forward(self.owner, self.organization, self.network_id, values))

    def refused(self, code, **body):
        with self.assertRaises(NetworkError) as raised: self.forward(**body)
        self.assertEqual(raised.exception.code, code)

    def received(self, cipher, address):
        packets = self.server.server.packets
        found = [IP(cipher.decrypt(packet)) for packet, to in packets
                 if to == address and Protocol.packet_type(packet) == Protocol.data]
        packets[:] = [item for item in packets if item[1] != address]
        return found

    def send(self, cipher, address, packet):
        self.server.send_packet((cipher.encrypt(packet), address))

    # ---------- Rules ----------

    def test_a_rule_needs_a_free_address_of_its_network(self):
        for address, code in (('10.1.0.5', 'invalid_address'), ('10.0.0.0', 'invalid_address'),
                              ('10.0.0.255', 'invalid_address'), ('nope', 'invalid_address'),
                              ('10.0.0.1', 'address_in_use'), ('10.0.0.254', 'address_in_use')):
            self.refused(code, address=address)
        self.forward()
        self.refused('forward_conflict')
        self.refused('forward_conflict', port=None, protocol='both')
        self.forward(port=7001)
        self.forward(protocol='tcp')
        self.assertEqual(len(self.admin.forwards(self.organization, self.network_id)), 3)

    def test_an_all_ports_rule_takes_the_whole_address(self):
        self.forward(port=None)
        self.refused('forward_conflict', port=9)
        self.forward(port=None, protocol='tcp')
        self.refused('forward_conflict', port=1, protocol='both')

    def test_ports_and_protocols_are_checked(self):
        for fields, code in ((dict(port=0), 'invalid_port'), (dict(port=65536), 'invalid_port'),
                             (dict(port='80'), 'invalid_port'), (dict(target_port=0), 'invalid_port'),
                             (dict(port=None, target_port=80), 'invalid_port'),
                             (dict(protocol='icmp'), 'invalid_request'), (dict(enabled='yes'), 'invalid_request'),
                             (dict(name='x' * 41), 'invalid_name')):
            self.refused(code, **fields)

    def test_the_target_is_an_organization_host_or_the_internet(self):
        for target in ('10.1.0.0', '10.1.0.255', '10.1.0.254', '192.168.1.1', '127.0.0.1', '::1', None, '10.0.0.50'):
            self.refused('invalid_target', target=target)
        self.forward(address='10.0.0.51', target='10.0.0.60')
        self.refused('invalid_target', address='10.0.0.60', target='10.0.0.51')
        # The internet needs the server and the network to allow it.
        self.refused('internet_disabled', target='8.8.8.8')
        self.server.internet = True
        self.refused('internet_disabled', target='8.8.8.8')
        Network(self.collections['networks'], self.network_id).update(internet=True)
        self.forward(target='8.8.8.8', port=None)

    def test_rules_are_edited_and_deleted(self):
        forward_id = self.forward()['result']['id']
        body = dict(address='10.0.0.50', port=7000, protocol='udp', target='10.1.0.1', target_port=9, enabled=False)
        effects = self.admin.update_forward(self.owner, self.organization, self.network_id, forward_id, body)
        self.assertEqual(effects['forwards'], (self.organization, {}))
        row, = self.admin.forwards(self.organization, self.network_id)
        self.assertEqual((row['target_port'], row['state']), (9, 'off'))
        # Saving a rule over itself is not a conflict.
        self.admin.update_forward(self.owner, self.organization, self.network_id, forward_id, dict(body, enabled=True))
        with self.assertRaises(NetworkError):
            self.admin.update_forward(self.owner, self.organization, self.network_id, 'nope', body)
        effects = self.admin.delete_forward(self.owner, self.organization, self.network_id, forward_id)
        self.assertEqual((effects['event']['kind'], self.admin.forwards(self.organization, self.network_id)),
                         ('forward_removed', []))

    def test_rules_need_their_permission(self):
        self.organizations.grant(self.owner, self.organization, self.member, {'forwards:view': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.add_forward(self.member, self.organization, self.network_id, dict(address='10.0.0.50'))
        self.organizations.grant(self.owner, self.organization, self.member, {'forwards:add': 'all'})
        effects = self.admin.add_forward(self.member, self.organization, self.network_id, dict(
            address='10.0.0.50', port=None, protocol='both', target='10.1.0.1', target_port=None))
        for operation in (self.admin.update_forward, self.admin.delete_forward):
            with self.assertRaises(PermissionError):
                operation(self.member, self.organization, self.network_id, effects['result']['id'], *(
                    [{}] if operation == self.admin.update_forward else []))

    def test_a_limit_of_rules_per_network(self):
        with mock.patch('connection.access_admin.FORWARDS', 1):
            self.forward()
            self.refused('forward_limit', port=7001)

    def test_states_follow_the_target(self):
        self.server.internet = True
        Network(self.collections['networks'], self.network_id).update(internet=True)
        self.forward(target='8.8.8.8', port=None)
        self.forward(address='10.0.0.51')
        self.assertEqual([row['state'] for row in self.admin.forwards(self.organization, self.network_id)], ['ok', 'ok'])
        self.server.internet = False
        # The office network moves away: its old address leads nowhere.
        Network(self.collections['networks'], self.other).update(network_range='10.2.0.0/24')
        self.assertEqual([row['state'] for row in self.admin.forwards(self.organization, self.network_id)],
                         ['no_internet', 'no_target'])
        table = self.admin.table(self.organization)
        self.assertEqual([rule['target'] for rule in table[self.network_id]], ['8.8.8.8'])

    def test_the_table_resolves_each_target(self):
        self.forward()
        rules = self.admin.table(self.organization)[self.network_id]
        self.assertEqual([(rule['target_network'], rule['organization_id']) for rule in rules],
                         [(self.other, self.organization)])

    def test_assignments_leave_rule_addresses_alone(self):
        self.forward(address='10.0.0.3')
        newcomer = self.account('newcomer')
        self.assertEqual(self.organizations.join(newcomer, self.organization, self.network_id), '10.0.0.4')
        with self.assertRaises(NetworkError) as raised:
            self.server.network_admin.change(self.owner, self.organization, self.network_id,
                                             str(self.member), '10.0.0.3')
        self.assertEqual(raised.exception.code, 'address_in_use')
        with self.assertRaises(NetworkError) as raised:
            self.server.network_admin.update(self.owner, self.organization, self.network_id, router='10.0.0.3')
        self.assertEqual(raised.exception.code, 'address_in_use')

    def test_a_new_range_may_not_leave_rules_behind(self):
        self.forward(address='10.0.0.200')
        with self.assertRaises(NetworkError) as raised:
            self.server.network_admin.update(self.owner, self.organization, self.network_id, network_range='10.0.0.0/25',
                                             max_address=100)
        self.assertEqual(raised.exception.code, 'forwards_outside')
        # A range that still holds it reassigns everyone around the rule.
        self.server.network_admin.update(self.owner, self.organization, self.network_id, network_range='10.0.0.0/23')

    def test_network_writes_rebuild_the_table(self):
        self.forward()
        effects = self.admin.with_table(self.organization, lambda: self.server.network_admin.update(
            self.owner, self.organization, self.other, network_range='10.2.0.0/24'))
        self.assertEqual(effects['forwards'], (self.organization, {}))
        self.apply(effects)
        self.assertFalse(self.server.forwarding.listens(self.network_id, '10.0.0.50'))

    def test_the_server_loads_every_rule_at_start(self):
        self.forward()
        self.server.forwarding = Forwarding()
        self.server.load_forwards()
        self.assertTrue(self.server.forwarding.listens(self.network_id, '10.0.0.50'))

    # ---------- Routes ----------

    def route(self, actor=None, email='member@example.com', source=None):
        return self.apply(self.admin.add_route(actor or self.owner, self.organization, self.other, email,
                                               str(source or self.network_id)))

    def route_refused(self, code, **fields):
        with self.assertRaises(NetworkError) as raised: self.route(**fields)
        self.assertEqual(raised.exception.code, code)

    def test_a_member_enters_another_network_with_its_own_address(self):
        self.vpn('member', self.guest_address)
        effects = self.route(email='MEMBER@example.com')
        self.assertEqual((effects['result'], effects['event']['kind']), (dict(ip='10.0.0.2'), 'route_added'))
        row, = self.admin.routes(self.organization, self.other)
        self.assertEqual((row['username'], row['ip'], row['source_name'], row['source_range']),
                         ('member', '10.0.0.2', None, '10.0.0.0/24'))
        # Connected through its source network, it reconnects to receive the new route.
        self.assertFalse(self.server.registry.get_account(self.member).networks)
        cipher, _ = self.vpn('member', self.guest_address)
        session = self.server.registry.get_account(self.member)
        self.assertEqual({network.mode for network in session.networks.values()}, {'assigned', 'routed'})

    def test_only_sessions_in_the_source_network_reconnect(self):
        self.organizations.join(self.member, self.organization, self.other)
        third = Network(self.collections['networks'])
        third.create('10.2.0.0/24', 253, self.organization)
        self.vpn('member', self.guest_address, self.other)
        self.apply(self.admin.add_route(self.owner, self.organization, third.id, 'member@example.com',
                                        str(self.network_id)))
        self.assertTrue(self.server.registry.get_account(self.member).networks)
        self.server.reconnect(self.member, self.other)
        self.assertFalse(self.server.registry.get_account(self.member).networks)
        self.server.reconnect(ObjectId(), self.other)

    def test_a_route_needs_a_valid_source_and_a_member(self):
        self.route_refused('unknown_account', email='nobody@example.com')
        self.route_refused('unknown_account', email='')
        outsider = self.account('outsider')
        self.route_refused('unknown_account', email='outsider@example.com')
        self.route_refused('already_assigned', email='guest@example.com')
        self.route_refused('invalid_source', source=self.other)
        self.route_refused('invalid_source', source=ObjectId())
        self.route_refused('invalid_source', source='nope')
        third = Network(self.collections['networks'])
        third.create('10.2.0.0/24', 253, self.organization)
        self.route_refused('invalid_source', source=third.id)
        self.assertTrue(outsider)

    def test_routes_need_permission_and_less_access_than_the_actor(self):
        self.organizations.grant(self.owner, self.organization, self.member, {'addresses:add': 'all'})
        with self.assertRaises(PermissionError):
            self.route(actor=self.member, email='owner@example.com')
        with self.assertRaises(PermissionError):
            self.admin.remove_route(self.guest, self.organization, self.other, str(self.member))
        self.route(email='owner@example.com')
        self.organizations.grant(self.owner, self.organization, self.member, {'addresses:delete': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.remove_route(self.member, self.organization, self.other, str(self.owner))

    def test_a_route_is_removed(self):
        self.route()
        self.vpn('member', self.guest_address)
        effects = self.apply(self.admin.remove_route(self.owner, self.organization, self.other, str(self.member)))
        self.assertEqual((effects['event']['kind'], self.admin.routes(self.organization, self.other)),
                         ('route_removed', []))
        self.assertNotIn(str(self.other), self.collections['accounts'].find_one(dict(_id=self.member))['networks'])
        self.assertFalse(self.server.registry.get_account(self.member).networks)
        with self.assertRaises(NetworkError):
            self.admin.remove_route(self.owner, self.organization, self.other, str(self.member))

    # ---------- Through the panel ----------

    def test_the_panel_shows_what_the_viewer_may_see(self):
        self.forward()
        self.route()
        channel = self.open('owner', self.owner_address)
        cookie = self.login(channel)[1]
        status, _, content = self.request(channel, 'GET', f'/api/access?network={self.other}', cookie)
        self.assertEqual((status, [row['ip'] for row in content['routes']], content['forwards']), (200, ['10.0.0.2'], []))
        self.assertTrue(content['routes'][0]['actions']['delete'])
        self.assertTrue(all(content['can'].values()))
        content = self.request(channel, 'GET', f'/api/access?network={self.network_id}', cookie)[2]
        self.assertEqual([row['state'] for row in content['forwards']], ['ok'])
        self.assertEqual(self.request(channel, 'GET', f'/api/access?network={ObjectId()}', cookie)[0], 404)

    def test_the_panel_hides_both_lists_without_permission(self):
        channel = self.open('member', self.guest_address)
        cookie = self.login(channel)[1]
        self.assertEqual(self.request(channel, 'GET', f'/api/access?network={self.network_id}', cookie)[0], 403)
        self.organizations.grant(self.owner, self.organization, self.member, {'forwards:view': 'all'})
        self.server.refresh_member(self.organization, self.member)
        content = self.request(channel, 'GET', f'/api/access?network={self.network_id}', cookie)[2]
        self.assertEqual((content['routes'], content['forwards']), (None, []))

    def test_the_panel_saves_rules_and_logs_them(self):
        channel = self.open('owner', self.owner_address)
        cookie = self.login(channel)[1]
        body = dict(network_id=str(self.network_id), address='10.0.0.50', port=7000, protocol='udp',
                    target='10.1.0.1', target_port=None)
        status, _, content = self.request(channel, 'POST', '/api/forwards/add', cookie, body)
        self.assertEqual(status, 200)
        self.server.advance_bridges()
        self.assertTrue(self.server.forwarding.listens(self.network_id, '10.0.0.50'))
        status, _, content = self.request(channel, 'POST', '/api/forwards/add', cookie, body)
        self.assertEqual((status, content['code']), (400, 'forward_conflict'))
        body = dict(network_id=str(self.other), email='member@example.com', source_id=str(self.network_id))
        self.assertEqual(self.request(channel, 'POST', '/api/routes/add', cookie, body)[0], 200)
        events = [event['kind'] for event in self.request(channel, 'GET', '/api/logs', cookie)[2]['events']]
        self.assertTrue({'forward_added', 'route_added'} <= set(events))

    # ---------- Packets ----------

    def test_udp_crosses_to_another_network_and_back(self):
        self.forward()
        owner, owner_ip = self.vpn('owner', self.owner_address)
        guest, guest_ip = self.vpn('guest', self.guest_address, self.other)
        self.server.server.packets.clear()
        self.send(owner, self.owner_address, udp((owner_ip, 40000), ('10.0.0.50', 7000), b'hello'))
        arrived, = self.received(guest, self.guest_address)
        self.assertEqual((arrived.src, arrived.sport, arrived.dst, arrived.dport, bytes(arrived[UDP].payload)),
                         ('10.1.0.254', 20000, guest_ip, 7000, b'hello'))
        self.send(guest, self.guest_address, udp((guest_ip, 7000), ('10.1.0.254', 20000), b'answer'))
        answer, = self.received(owner, self.owner_address)
        self.assertEqual((answer.src, answer.sport, answer.dst, answer.dport, bytes(answer[UDP].payload)),
                         ('10.0.0.50', 7000, owner_ip, 40000, b'answer'))
        # Losing its routes ends what the session opened.
        self.server.disconnect(self.owner)
        self.assertEqual(self.server.forwarding.entries, 0)

    def test_tcp_connects_through_a_rule(self):
        self.forward(protocol='tcp', port=80, target_port=8080)
        owner, owner_ip = self.vpn('owner', self.owner_address)
        guest, guest_ip = self.vpn('guest', self.guest_address, self.other)
        client, server = TCPStack(owner_ip, seed=1), TCPStack(guest_ip, seed=2)
        listener = server.listen(8080)
        connection = client.connect('10.0.0.50', 80)
        accepted = None
        for _ in range(50):
            for packet in client.transmit(): self.send(owner, self.owner_address, packet)
            for packet in server.transmit(): self.send(guest, self.guest_address, packet)
            for packet in self.received(guest, self.guest_address): server.receive(bytes(packet))
            for packet in self.received(owner, self.owner_address): client.receive(bytes(packet))
            accepted = accepted or listener.accept()
            if accepted and connection.state == 'ESTABLISHED': break
        self.assertEqual(connection.state, 'ESTABLISHED')
        connection.send(b'through')
        for _ in range(10):
            for packet in client.transmit(): self.send(owner, self.owner_address, packet)
            for packet in self.received(guest, self.guest_address): server.receive(bytes(packet))
        self.assertEqual(accepted.receive(), b'through')

    def test_without_the_target_connected_nothing_arrives(self):
        self.forward()
        owner, owner_ip = self.vpn('owner', self.owner_address)
        self.server.server.packets.clear()
        self.send(owner, self.owner_address, udp((owner_ip, 40000), ('10.0.0.50', 7000)))
        self.assertEqual(self.server.server.packets, [])
        # A port the rule does not open is dropped too, not sent anywhere.
        self.send(owner, self.owner_address, udp((owner_ip, 40000), ('10.0.0.50', 7001)))
        self.assertEqual((self.server.server.packets, self.server.egress.flows), ([], 0))

    def test_the_panel_still_answers_its_own_address(self):
        self.forward()
        channel = self.open('owner', self.owner_address)
        self.assertEqual(self.request(channel, 'GET', '/api/me', None)[0], 200)

    def test_internet_targets_leave_through_the_egress(self):
        remote = Loopback()
        self.addCleanup(remote.close)
        self.server.internet, self.server.egress.allowed = True, lambda address: True
        Network(self.collections['networks'], self.network_id).update(internet=True)
        network = Network(self.collections['networks'], self.network_id)
        forwards = [dict(id='r', name=None, address='10.0.0.60', port=None, protocol='udp', target='127.0.0.1',
                         target_port=None, enabled=True)]
        network.update(forwards=forwards)
        table = {self.network_id: [dict(forwards[0], organization_id=self.organization, target_network=None)]}
        self.server.forwarding.install(self.organization, table)
        owner, owner_ip = self.vpn('owner', self.owner_address)
        self.server.server.packets.clear()
        self.send(owner, self.owner_address, udp((owner_ip, 40000), ('10.0.0.60', remote.udp_port), b'out'))
        replies = []
        for _ in range(100):
            readable = select.select(self.server.egress.readers(), [], [], 0.01)[0]
            self.server.egress.ready(readable, [], [])
            remote.echo_udp()
            replies += self.received(owner, self.owner_address)
            if replies: break
        reply, = replies
        self.assertEqual((reply.src, reply.sport, bytes(reply[UDP].payload)), ('10.0.0.60', remote.udp_port, b'OUT'))
        # The network closes its internet: the rule stops leaving.
        self.server.disconnect(self.owner)
        Network(self.collections['networks'], self.network_id).update(internet=False)
        owner, owner_ip = self.vpn('owner', self.owner_address)
        self.send(owner, self.owner_address, udp((owner_ip, 40001), ('10.0.0.60', remote.udp_port), b'out'))
        self.assertEqual(self.server.egress.flows, 0)


if __name__ == '__main__':
    unittest.main()
