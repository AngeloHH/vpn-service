import time
import unittest
from unittest import mock

from bson import ObjectId
from scapy.layers.inet import ICMP, IP, TCP, UDP

from connection import firewall as module
from connection.database.mongodb import Network
from connection.firewall import Firewall, endpoints
from connection.network_admin import NetworkError
from connection.protocol import Protocol
from tests.panel import Panel

NETWORK = ObjectId()
ROLE = ObjectId()


class Member:
    def __init__(self, role_id=None):
        self.account_id, self.role_id = ObjectId(), role_id


def side(kind='any', owner=None):
    return dict(kind=kind) if kind == 'any' else dict(kind=kind, id=owner.__str__())


def rule(action='block', source=None, destination=None, protocol='any', port=None):
    return dict(id='r', action=action, source=source or side(), destination=destination or side(),
                protocol=protocol, port=port, enabled=True)


def udp(source, destination, sport=40000, dport=53):
    return bytes(IP(src=source, dst=destination) / UDP(sport=sport, dport=dport) / b'x')


def tcp(source, destination, sport=40000, dport=80):
    return bytes(IP(src=source, dst=destination) / TCP(sport=sport, dport=dport))


class FirewallTest(unittest.TestCase):
    def setUp(self):
        self.firewall, self.alice, self.bob = Firewall(), Member(ROLE), Member()

    def install(self, isolated=False, *rules):
        self.firewall.install('org', {NETWORK: dict(isolated=isolated, rules=list(rules))})

    def allows(self, packet, sender=None, receiver=None):
        return self.firewall.allows(NETWORK, sender or self.alice, receiver or self.bob, packet)

    def test_networks_without_rules_are_open(self):
        self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2')))
        self.assertTrue(self.firewall.allows(ObjectId(), self.alice, self.bob, b'garbage'))
        self.assertEqual(self.firewall.flows, {})

    def test_isolation_refuses_without_a_rule(self):
        self.install(True)
        self.assertFalse(self.allows(udp('10.0.0.1', '10.0.0.2')))
        self.assertFalse(self.allows(b'short'))

    def test_the_first_matching_rule_decides(self):
        self.install(False, rule('allow', side('account', self.alice.account_id)), rule('block'))
        self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2')))
        self.assertFalse(self.allows(udp('10.0.0.2', '10.0.0.1'), self.bob, self.alice))

    def test_sides_match_people_and_roles(self):
        self.install(False, rule(source=side('role', ROLE)))
        self.assertFalse(self.allows(udp('10.0.0.1', '10.0.0.2')))
        self.assertTrue(self.allows(udp('10.0.0.2', '10.0.0.1'), self.bob, self.alice))
        self.install(False, rule(destination=side('account', self.bob.account_id)))
        self.assertFalse(self.allows(udp('10.0.0.1', '10.0.0.2', 1)))
        self.assertTrue(self.allows(udp('10.0.0.2', '10.0.0.1', 2), self.bob, self.alice))
        self.install(False, rule(source=side('role', ObjectId())))
        self.assertTrue(self.allows(udp('10.0.0.2', '10.0.0.1', 3), self.bob, self.alice))
        self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2', 4)))

    def test_protocol_and_port_narrow_a_rule(self):
        self.install(True, rule('allow', protocol='tcp', port=80))
        self.assertTrue(self.allows(tcp('10.0.0.1', '10.0.0.2', dport=80)))
        self.assertFalse(self.allows(tcp('10.0.0.1', '10.0.0.2', dport=81)))
        self.assertFalse(self.allows(udp('10.0.0.1', '10.0.0.2', dport=80)))
        self.assertFalse(self.allows(bytes(IP(src='10.0.0.1', dst='10.0.0.2') / ICMP())))
        self.install(True, rule('allow', protocol='udp'))
        self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2', dport=9)))
        self.assertFalse(self.allows(tcp('10.0.0.1', '10.0.0.2', dport=9)))
        self.install(True, rule('allow'))
        self.assertTrue(self.allows(bytes(IP(src='10.0.0.1', dst='10.0.0.2') / ICMP())))

    def test_answers_of_an_allowed_conversation_return(self):
        self.install(True, rule('allow', side('account', self.alice.account_id)))
        self.assertTrue(self.allows(tcp('10.0.0.1', '10.0.0.2', 40000, 80)))
        self.assertTrue(self.allows(tcp('10.0.0.2', '10.0.0.1', 80, 40000), self.bob, self.alice))
        # Not another port of the same people.
        self.assertFalse(self.allows(tcp('10.0.0.2', '10.0.0.1', 80, 40001), self.bob, self.alice))
        # Ping answers come back too.
        ping = bytes(IP(src='10.0.0.1', dst='10.0.0.2') / ICMP())
        self.assertTrue(self.allows(ping))
        self.assertTrue(self.allows(bytes(IP(src='10.0.0.2', dst='10.0.0.1') / ICMP(type=0)), self.bob, self.alice))

    def test_new_rules_reach_open_conversations(self):
        self.install(False)
        self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2')))
        self.install(False, rule())
        self.assertFalse(self.allows(udp('10.0.0.1', '10.0.0.2')))
        # Another organization's change keeps these conversations.
        self.install(False, rule('allow'))
        self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2')))
        self.firewall.install('another', {ObjectId(): dict(isolated=True, rules=[])})
        self.assertEqual(len(self.firewall.flows), 1)
        # Emptying the organization opens the network and forgets its conversations.
        self.firewall.install('org', {})
        self.assertEqual((self.firewall.flows, NETWORK in self.firewall.networks), ({}, False))

    def test_conversations_expire_by_protocol(self):
        self.install(False, rule('allow'))
        self.allows(tcp('10.0.0.1', '10.0.0.2')), self.allows(udp('10.0.0.1', '10.0.0.2'))
        now = time.monotonic()
        self.firewall.advance(now + 0.5)
        # Swept once a second: a turn right after the last sweep keeps everything.
        self.firewall.advance(now + module.OTHER_IDLE - 0.5)
        self.firewall.advance(now + module.OTHER_IDLE + 0.4)
        self.assertEqual(len(self.firewall.flows), 2)
        self.firewall.advance(now + module.OTHER_IDLE + 2)
        self.assertEqual([key[1] for key in self.firewall.flows], [6])
        self.firewall.advance(now + module.OTHER_IDLE + 2.5)
        self.firewall.advance(now + module.TCP_IDLE + 5)
        self.assertEqual(self.firewall.flows, {})

    def test_the_table_of_conversations_has_a_ceiling(self):
        self.install(True, rule('allow', side('account', self.alice.account_id)))
        with mock.patch.object(module, 'FLOWS', 1):
            self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2', 1)))
            self.assertTrue(self.allows(udp('10.0.0.1', '10.0.0.2', 2)))
            self.assertEqual(len(self.firewall.flows), 1)
            # Without room the answer faces the rules, which refuse it.
            self.assertFalse(self.allows(udp('10.0.0.2', '10.0.0.1', 53, 2), self.bob, self.alice))
            self.assertTrue(self.allows(udp('10.0.0.2', '10.0.0.1', 53, 1), self.bob, self.alice))

    def test_endpoints_of_fragments_have_no_ports(self):
        packet = bytes(IP(src='10.0.0.1', dst='10.0.0.2', frag=10) / UDP(sport=1, dport=2))
        self.assertEqual(endpoints(packet), (17, ('10.0.0.1', 0), ('10.0.0.2', 0)))
        self.assertIsNone(endpoints(b'\x60' + b'\0' * 39))


class SecurityTest(Panel, unittest.TestCase):
    owner_address, member_address = ('127.0.0.1', 52000), ('127.0.0.1', 52001)

    def setUp(self):
        super().setUp()
        self.admin = self.server.security_admin
        self.role = self.organizations.create_role(self.owner, self.organization, 'Soporte', {})

    def apply(self, effects):
        self.server.complete_change(dict(effects, organization_id=self.organization))
        return effects

    def add(self, actor=None, **body):
        values = dict(action='block', source=dict(kind='any'), destination=dict(kind='any'), protocol='any', port=None)
        values.update(body)
        return self.apply(self.admin.add_rule(actor or self.owner, self.organization, self.network_id, values))

    def refused(self, code, **body):
        with self.assertRaises(NetworkError) as raised: self.add(**body)
        self.assertEqual(raised.exception.code, code)

    def rules(self):
        return self.admin.security(self.organization, self.network_id)['rules']

    def test_rules_are_validated(self):
        for body, code in ((dict(action='drop'), 'invalid_rule'), (dict(protocol='icmp'), 'invalid_rule'),
                           (dict(port=80), 'port_needs_protocol'), (dict(protocol='tcp', port=0), 'invalid_port'),
                           (dict(protocol='tcp', port='80'), 'invalid_port'), (dict(enabled=1), 'invalid_rule'),
                           (dict(source=dict(kind='everyone')), 'invalid_rule'), (dict(source='any'), 'invalid_rule'),
                           (dict(source=dict(kind='role', id='nope')), 'invalid_rule'),
                           (dict(source=dict(kind='role', id=str(ObjectId()))), 'invalid_rule'),
                           (dict(source=dict(kind='account')), 'invalid_rule'),
                           (dict(source=dict(kind='account', id=str(ObjectId()))), 'account_not_found'),
                           (dict(source=dict(kind='account', email='nobody@example.com')), 'unknown_account')):
            self.refused(code, **body)

    def test_people_are_chosen_by_email_and_shown_by_name(self):
        self.add(source=dict(kind='account', email='MEMBER@example.com'), destination=dict(kind='role', id=str(self.role)),
                 protocol='tcp', port=22)
        rule, = self.rules()
        self.assertEqual((rule['source']['id'], rule['source']['name'], rule['destination']['name'], rule['port']),
                         (str(self.member), 'member', 'Soporte', 22))
        roles = self.admin.security(self.organization, self.network_id)['roles']
        self.assertEqual([role['name'] for role in roles], ['Administrador', 'Soporte'])

    def test_rules_are_edited_moved_and_deleted(self):
        first = self.add()['result']['id']
        second = self.add(action='allow')['result']['id']
        self.apply(self.admin.move_rule(self.owner, self.organization, self.network_id, second, -1))
        self.assertEqual([rule['id'] for rule in self.rules()], [second, first])
        for step in (-1, 0, 2):
            with self.assertRaises(NetworkError):
                self.admin.move_rule(self.owner, self.organization, self.network_id, second, step)
        body = dict(action='allow', source=dict(kind='any'), destination=dict(kind='any'), enabled=False)
        self.apply(self.admin.update_rule(self.owner, self.organization, self.network_id, first, body))
        self.assertEqual((self.rules()[1]['action'], self.rules()[1]['enabled']), ('allow', False))
        # Disabled rules stay out of the packet path.
        self.assertEqual(len(self.server.firewall.networks[self.network_id]['rules']), 1)
        effects = self.admin.delete_rule(self.owner, self.organization, self.network_id, second)
        self.assertEqual((effects['event']['kind'], effects['firewall'][1]), ('rule_removed', {}))
        with self.assertRaises(NetworkError):
            self.admin.delete_rule(self.owner, self.organization, self.network_id, second)

    def test_isolation_is_a_switch(self):
        effects = self.apply(self.admin.set_isolated(self.owner, self.organization, self.network_id, True))
        self.assertEqual(effects['firewall'][1], {self.network_id: dict(isolated=True, rules=[])})
        self.assertTrue(self.admin.security(self.organization, self.network_id)['isolated'])
        with self.assertRaises(NetworkError):
            self.admin.set_isolated(self.owner, self.organization, self.network_id, 'yes')

    def test_rules_need_permission_and_less_access(self):
        with self.assertRaises(PermissionError): self.add(actor=self.member)
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'rules:add': 'all', 'rules:modify': 'all', 'rules:delete': 'all'})
        self.add(actor=self.member)
        with self.assertRaises(PermissionError):
            self.add(actor=self.member, destination=dict(kind='account', id=str(self.owner)))
        administrator = self.collections['roles'].documents[0]['_id']
        with self.assertRaises(PermissionError):
            self.add(actor=self.member, source=dict(kind='role', id=str(administrator)))
        # A rule about the owner, written by the owner, stays out of the member's reach.
        about_owner = self.add(destination=dict(kind='account', id=str(self.owner)))['result']['id']
        for operation, extra in ((self.admin.delete_rule, ()), (self.admin.update_rule, (dict(action='allow'),))):
            with self.assertRaises(PermissionError):
                operation(self.member, self.organization, self.network_id, about_owner, *extra)

    def test_a_rule_about_someone_gone_can_still_be_removed(self):
        rule_id = self.add(source=dict(kind='role', id=str(self.role)))['result']['id']
        self.organizations.delete_role(self.owner, self.organization, self.role)
        self.assertIsNone(self.rules()[0]['source']['name'])
        self.organizations.grant(self.owner, self.organization, self.member, {'rules:delete': 'all'})
        self.admin.delete_rule(self.member, self.organization, self.network_id, rule_id)

    def test_a_limit_of_rules_per_network(self):
        with mock.patch('connection.security_admin.RULES', 1):
            self.add()
            self.refused('rule_limit')

    def test_the_server_loads_the_rules_at_start(self):
        self.add()
        self.server.firewall = Firewall()
        self.server.load_forwards()
        self.assertIn(self.network_id, self.server.firewall.networks)

    # ---------- Packets ----------

    def received(self, cipher, address):
        packets = self.server.server.packets
        found = [IP(cipher.decrypt(packet)) for packet, to in packets
                 if to == address and Protocol.packet_type(packet) == Protocol.data]
        packets[:] = [item for item in packets if item[1] != address]
        return found

    def test_isolated_members_only_reach_what_a_rule_allows(self):
        owner, owner_ip = self.vpn('owner', self.owner_address)
        member, member_ip = self.vpn('member', self.member_address)
        self.server.server.packets.clear()
        send = lambda cipher, address, packet: self.server.send_packet((cipher.encrypt(packet), address))
        self.apply(self.admin.set_isolated(self.owner, self.organization, self.network_id, True))
        send(owner, self.owner_address, udp(owner_ip, member_ip))
        self.assertEqual(self.received(member, self.member_address), [])
        self.add(action='allow', source=dict(kind='account', id=str(self.owner)), protocol='udp', port=53)
        send(owner, self.owner_address, udp(owner_ip, member_ip))
        self.assertEqual(len(self.received(member, self.member_address)), 1)
        # The answer returns; the member cannot start its own conversation.
        send(member, self.member_address, udp(member_ip, owner_ip, 53, 40000))
        self.assertEqual(len(self.received(owner, self.owner_address)), 1)
        send(member, self.member_address, udp(member_ip, owner_ip, 53, 40001))
        self.assertEqual(self.received(owner, self.owner_address), [])
        # The panel never depends on these rules.
        channel = self.open('member', self.member_address)
        self.assertEqual(self.request(channel, 'GET', '/api/me', None)[0], 200)

    # ---------- Through the panel ----------

    def test_the_panel_reads_and_writes_rules(self):
        channel = self.open('owner', self.owner_address)
        cookie = self.login(channel)[1]
        body = dict(network_id=str(self.network_id), action='block', source=dict(kind='any'),
                    destination=dict(kind='role', id=str(self.role)), protocol='tcp', port=22)
        self.assertEqual(self.request(channel, 'POST', '/api/security/rules/add', cookie, body)[0], 200)
        body = dict(network_id=str(self.network_id), isolated=True)
        self.assertEqual(self.request(channel, 'POST', '/api/security/isolated', cookie, body)[0], 200)
        status, _, content = self.request(channel, 'GET', f'/api/security?network={self.network_id}', cookie)
        self.assertEqual((status, content['isolated'], len(content['rules']), all(content['can'].values())),
                         (200, True, 1, True))
        self.assertEqual(self.request(channel, 'GET', f'/api/security?network={ObjectId()}', cookie)[0], 404)
        events = [event['kind'] for event in self.request(channel, 'GET', '/api/logs', cookie)[2]['events']]
        self.assertTrue({'rule_added', 'isolation_changed'} <= set(events))

    def test_the_rules_are_hidden_without_permission(self):
        channel = self.open('member', self.member_address)
        cookie = self.login(channel)[1]
        self.assertEqual(self.request(channel, 'GET', f'/api/security?network={self.network_id}', cookie)[0], 403)


class ConsumptionTest(Panel, unittest.TestCase):
    address = ('127.0.0.1', 53000)

    def setUp(self):
        super().setUp()
        self.channel = self.open('owner', self.address)
        self.cookie = self.login(self.channel)[1]
        self.period = self.server.usage.period

    def usage(self, query=''):
        return self.request(self.channel, 'GET', '/api/usage' + query, self.cookie)

    def document(self, account_id, scope, **fields):
        self.collections['usage'].documents.append(dict(organization_id=str(self.organization), account_id=str(account_id),
                                                        scope=scope, period=self.period, **fields))

    def test_members_are_listed_by_consumption_with_their_quota(self):
        scope = str(self.network_id)
        self.document(self.member, scope, down=5_000_000, up=1_000_000, extra_down=2_000_000)
        # Another month does not count.
        self.collections['usage'].documents.append(dict(organization_id=str(self.organization), account_id=str(self.owner),
                                                        scope=scope, period='2000-01', down=10**12, up=0))
        limits = dict(roles={}, members={str(self.member): dict(quota_down=10, quota_up=None)})
        Network(self.collections['networks'], self.network_id).update(limits=limits)
        status, _, content = self.usage(f'?network={self.network_id}')
        self.assertEqual((status, content['total'], content['period']), (200, 2, self.period))
        first = content['rows'][0]
        self.assertEqual((first['username'], first['down'], first['up'], first['quota_down'], first['quota_up'],
                          first['extra_down']), ('member', 5_000_000, 1_000_000, 10, None, 2_000_000))
        self.assertEqual(content['rows'][1]['username'], 'owner')

    def test_counters_in_memory_are_ahead_of_the_database(self):
        key = (str(self.organization), str(self.owner), str(self.network_id))
        self.server.usage.spent(key)
        self.server.usage.add(key, 0, 9_000_000)
        stored = self.usage(f'?network={self.network_id}')[2]['rows']
        # The panel's own traffic is not counted: the member row stays at zero.
        self.assertEqual([(row['username'], row['down']) for row in stored], [('owner', 9_000_000), ('member', 0)])

    def test_role_extras_and_quotas_apply_to_their_members(self):
        role = self.organizations.create_role(self.owner, self.organization, 'Soporte', {})
        self.organizations.assign_role(self.owner, self.organization, self.member, role)
        self.collections['usage'].documents.append(dict(organization_id=str(self.organization), role_id=str(role),
                                                        scope='internet', period=self.period, extra_up=3_000_000))
        from connection.database.mongodb import Organization
        Organization(self.collections['organizations'], self.organization).update(
            internet_limits=dict(roles={str(role): dict(quota_up=1)}, members={}))
        rows = {row['username']: row for row in self.usage()[2]['rows']}
        self.assertEqual((rows['member']['quota_up'], rows['member']['extra_up']), (1, 3_000_000))
        self.assertEqual((rows['owner']['quota_up'], rows['owner']['extra_up']), (None, 0))

    def test_pages_and_permissions(self):
        for index in range(3): self.organizations.join(self.account(f'user{index}'), self.organization, self.network_id)
        content = self.usage(f'?network={self.network_id}&offset=1&limit=2')[2]
        self.assertEqual((content['total'], len(content['rows'])), (5, 2))
        self.assertEqual(self.usage(f'?network={ObjectId()}')[0], 404)
        member = self.open('member', ('127.0.0.1', 53001))
        cookie = self.login(member)[1]
        self.assertEqual(self.request(member, 'GET', '/api/usage', cookie)[0], 403)


if __name__ == '__main__':
    unittest.main()
