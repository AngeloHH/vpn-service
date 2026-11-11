import unittest
from unittest import mock

from bson import ObjectId

from connection import network_admin
from connection.admin import register_admin
from connection.database.mongodb import Account, Member, Network
from connection.network_admin import Confirmation, NetworkError
from connection.protocol import Control, Protocol
from tests.panel import PANEL, Panel


class NetworkAdminTest(Panel, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.server.network_admin

    def network(self, network_id):
        return Network(self.collections['networks'], network_id).get()

    def account_networks(self, account_id):
        return Account(self.collections['accounts'], account_id).get()['networks']

    def create(self, network_range='10.1.0.0/24', **fields):
        result = self.admin.create(self.owner, self.organization, network_range, **fields)
        return ObjectId(result['result']['network_id'])

    def refused(self, code, operation, *arguments, **fields):
        with self.assertRaises(NetworkError) as raised: operation(*arguments, **fields)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_a_new_network_takes_its_last_host_for_the_panel(self):
        effects = self.admin.create(self.owner, self.organization, '10.1.0.7/24', name=' Oficina ')
        network = self.network(effects['result']['network_id'])

        self.assertEqual(network['server'], dict(ip_address='10.1.0.254', port=80))
        self.assertEqual((network['network_range'], network['name'], network['max_address']),
                         ('10.1.0.0/24', 'Oficina', 253))
        self.assertEqual(effects['panel'], ('add', network['_id']))

    def test_ranges_must_be_valid_and_separate(self):
        create = self.admin.create
        for invalid in ('10.1.0.0/31', 'fd00::/64', 'nope', None):
            self.refused('invalid_range', create, self.owner, self.organization, invalid)
        overlap = self.refused('range_overlap', create, self.owner, self.organization, '10.0.0.128/25')
        self.assertEqual(overlap.fields['network_range'], '10.0.0.0/24')
        self.refused('invalid_limit', create, self.owner, self.organization, '10.1.0.0/24', 254)
        self.refused('invalid_name', create, self.owner, self.organization, '10.1.0.0/24', name='x' * 41)

    def test_creating_needs_the_permission_for_every_network(self):
        with self.assertRaises(PermissionError):
            self.admin.create(self.member, self.organization, '10.1.0.0/24')
        # A primary scope does not reach a network that does not exist yet.
        self.organizations.grant(self.owner, self.organization, self.member, {'networks:add': 'primary'})
        with self.assertRaises(PermissionError):
            self.admin.create(self.member, self.organization, '10.1.0.0/24')
        self.organizations.grant(self.owner, self.organization, self.member, {'networks:add': 'all'})
        self.admin.create(self.member, self.organization, '10.1.0.0/24')

    def test_the_limit_never_drops_below_the_addresses_in_use(self):
        update = self.admin.update
        refused = self.refused('limit_in_use', update, self.owner, self.organization,
                               self.network_id, max_address=1)
        self.assertEqual(refused.fields['used'], 2)
        effects = update(self.owner, self.organization, self.network_id, name='Casa', max_address=2)
        self.assertEqual((self.network(self.network_id)['name'], self.network(self.network_id)['max_address']),
                         ('Casa', 2))
        # Neither the name nor the limit changes anyone's configuration.
        self.assertEqual((effects['disconnect'], effects.get('panel')), ([], None))

    def test_opening_the_internet_reconnects_the_members(self):
        self.assertFalse(self.network(self.network_id)['internet'])
        # Without the server's own switch, no network may open it.
        self.refused('internet_disabled', self.admin.update, self.owner, self.organization,
                     self.network_id, internet=True)
        self.server.internet = True
        self.refused('invalid_request', self.admin.update, self.owner, self.organization,
                     self.network_id, internet='yes')
        effects = self.admin.update(self.owner, self.organization, self.network_id, internet=True)
        self.assertTrue(self.network(self.network_id)['internet'])
        self.assertEqual((set(effects['disconnect']), effects.get('panel')), ({self.owner, self.member}, None))
        # Saving the same value changes nobody's configuration.
        effects = self.admin.update(self.owner, self.organization, self.network_id, internet=True)
        self.assertEqual(effects['disconnect'], [])

    def test_each_network_has_its_own_dns_servers(self):
        update = self.admin.update
        for invalid in ('1.1.1.1', ['1.1.1.1', '8.8.8.8', '9.9.9.9'], ['fd00::1'], ['224.0.0.1'],
                        ['0.0.0.0'], ['dns.google'], [53]):
            self.refused('invalid_dns', update, self.owner, self.organization, self.network_id, dns=invalid)
        office = self.create('10.1.0.0/24')
        effects = update(self.owner, self.organization, self.network_id, dns=['10.0.0.53', '10.0.0.53'])
        self.assertEqual(self.network(self.network_id)['dns'], ['10.0.0.53'])
        self.assertEqual(self.network(office)['dns'], [])
        # New servers reach the members when they reconnect.
        self.assertEqual(set(effects['disconnect']), {self.owner, self.member})
        self.assertEqual(effects['event']['changes'], ['dns'])
        self.assertEqual(update(self.owner, self.organization, self.network_id, dns=['10.0.0.53'])['disconnect'], [])
        update(self.owner, self.organization, self.network_id, dns=[])
        self.assertEqual(self.network(self.network_id)['dns'], [])

    def test_a_new_range_reassigns_every_address_from_the_start(self):
        office = self.create('10.1.0.0/24')
        Network(self.collections['networks'], office).to_network(
            Account(self.collections['accounts'], self.member), 'routed', self.network_id)
        connections = self.network(self.network_id)['connections']
        connections[str(self.owner)], connections[str(self.member)] = '10.0.0.9', '10.0.0.4'

        effects = self.admin.update(self.owner, self.organization, self.network_id,
                                    network_range='10.5.0.0/24')
        network = self.network(self.network_id)

        self.assertEqual(network['connections'], {str(self.member): '10.5.0.1', str(self.owner): '10.5.0.2'})
        self.assertEqual((network['subnet_mask'], network['server']['ip_address']),
                         ('255.255.255.0', '10.5.0.254'))
        # The routed network keeps reusing the member's new identity.
        self.assertEqual(self.network(office)['routes'], {str(self.member): '10.5.0.1'})
        self.assertEqual(set(effects['disconnect']), {self.owner, self.member})
        self.assertEqual(effects['panel'], ('move', self.network_id))

    def test_a_range_may_grow_over_itself_around_the_panel(self):
        self.admin.update(self.owner, self.organization, self.network_id,
                          network_range='10.0.0.0/23', router='10.0.0.1')
        network = self.network(self.network_id)
        self.assertEqual(network['network_range'], '10.0.0.0/23')
        # Members skip the address the panel took.
        self.assertEqual(sorted(network['connections'].values()), ['10.0.0.2', '10.0.0.3'])

    def test_the_panel_cannot_take_a_routed_address(self):
        # Another organization may reuse the range, so a routed identity can fall inside it.
        office = self.create('10.1.0.0/24')
        visitor = self.account('visitor')
        self.organizations.create(visitor, network_range='10.1.0.0/24')
        source = next(network['_id'] for network in self.collections['networks'].documents
                      if str(visitor) in network['connections'])
        Network(self.collections['networks'], office).to_network(
            Account(self.collections['accounts'], visitor), 'routed', source)
        self.refused('address_in_use', self.admin.update, self.owner, self.organization, office,
                     router='10.1.0.1')

    def test_the_panel_address_must_be_a_free_host(self):
        update = self.admin.update
        for invalid in ('10.0.0.0', '10.0.0.255', '10.1.0.5', 'x'):
            self.refused('invalid_address', update, self.owner, self.organization, self.network_id, router=invalid)
        self.refused('address_in_use', update, self.owner, self.organization, self.network_id, router='10.0.0.2')
        effects = update(self.owner, self.organization, self.network_id, router='10.0.0.200')
        self.assertEqual(self.network(self.network_id)['server']['ip_address'], '10.0.0.200')
        self.assertEqual(effects['panel'], ('move', self.network_id))

    def test_a_deleted_network_moves_its_members_to_their_next_network(self):
        office = self.create('10.1.0.0/24')
        self.organizations.join(self.owner, self.organization, office)
        guest = self.account('guest')
        self.organizations.join(guest, self.organization, self.network_id)

        with self.assertRaises(Confirmation) as pending:
            self.admin.delete(self.owner, self.organization, self.network_id)
        leaving = [account['username'] for account in pending.exception.accounts]
        self.assertEqual(sorted(leaving), ['guest', 'member'])
        self.assertIsNotNone(self.network(self.network_id))

        effects = self.admin.delete(self.owner, self.organization, self.network_id, confirm=True)
        self.assertIsNone(self.network(self.network_id))
        self.assertEqual(self.account_networks(self.owner), {str(office): dict(mode='assigned', primary=True)})
        self.assertEqual((effects['disconnect'], sorted(map(str, effects['kick']))),
                         ([self.owner], sorted([str(self.member), str(guest)])))
        members = Member(self.collections['members'])
        self.assertIsNone(members.get(organization_id=self.organization, account_id=self.member))
        self.assertEqual(effects['panel'], ('remove', self.network_id))

    def test_the_last_network_cannot_be_deleted(self):
        self.refused('last_network', self.admin.delete, self.owner, self.organization, self.network_id, True)

    def test_assignments_add_existing_accounts_only(self):
        office = self.create('10.1.0.0/24', max_address=1)
        add = self.admin.add
        self.refused('unknown_account', add, self.owner, self.organization, office, 'nobody@example.com')
        # The whole address must match; upper and lower case do not matter.
        self.refused('unknown_account', add, self.owner, self.organization, office, 'member@example')
        self.refused('unknown_account', add, self.owner, self.organization, office, '.*@example.com')
        effects = add(self.owner, self.organization, office, ' Member@Example.COM ')
        self.assertEqual(effects['result']['ip'], '10.1.0.1')
        self.refused('already_assigned', add, self.owner, self.organization, office, 'member@example.com')
        self.refused('exhausted', add, self.owner, self.organization, office, 'owner@example.com')
        page = self.admin.assignments(self.organization, office)
        self.assertEqual([(row['username'], row['ip'], row['primary']) for row in page['rows']],
                         [('member', '10.1.0.1', False)])

    def test_assignments_come_in_pages_ordered_by_address(self):
        for number in range(30):
            self.organizations.join(self.account(f'user{number:02d}'), self.organization, self.network_id)
        first = self.admin.assignments(self.organization, self.network_id)
        second = self.admin.assignments(self.organization, self.network_id, offset=25)

        self.assertEqual((len(first['rows']), len(second['rows']), first['total']), (25, 7, 32))
        addresses = [row['ip'] for row in first['rows'] + second['rows']]
        self.assertEqual(addresses, [f'10.0.0.{host}' for host in range(1, 33)])
        # Out-of-range numbers are clamped instead of failing or reading everything.
        odd = self.admin.assignments(self.organization, self.network_id, offset=-5, limit=0)
        self.assertEqual([row['ip'] for row in odd['rows']], ['10.0.0.1'])
        with mock.patch.object(network_admin, 'MAX_PAGE', 3):
            self.assertEqual(len(self.admin.assignments(self.organization, self.network_id, limit=9999)['rows']), 3)

    def test_a_form_loaded_before_another_change_is_refused(self):
        loaded = dict(name='', network_range='10.0.0.0/24', max_address=253, router=PANEL, internet=False, dns=[])
        self.admin.update(self.owner, self.organization, self.network_id, name='Casa', expected=loaded)
        self.refused('changed', self.admin.update, self.owner, self.organization, self.network_id,
                     max_address=100, expected=loaded)
        self.assertEqual(self.network(self.network_id)['max_address'], 253)
        self.refused('changed', self.admin.change, self.owner, self.organization, self.network_id,
                     self.member, '10.0.0.9', expected='10.0.0.7')
        self.admin.change(self.owner, self.organization, self.network_id, self.member, '10.0.0.9',
                          expected='10.0.0.2')

    def test_an_address_change_stays_inside_the_limit(self):
        change = self.admin.change
        self.refused('address_in_use', change, self.owner, self.organization, self.network_id, self.member, '10.0.0.1')
        self.admin.update(self.owner, self.organization, self.network_id, router='10.0.0.7')
        self.refused('address_in_use', change, self.owner, self.organization, self.network_id, self.member, '10.0.0.7')
        self.admin.update(self.owner, self.organization, self.network_id, max_address=10)
        self.refused('invalid_address', change, self.owner, self.organization, self.network_id, self.member, '10.0.0.11')
        self.refused('account_not_found', change, self.owner, self.organization, self.network_id, ObjectId(), '10.0.0.5')
        effects = change(self.owner, self.organization, self.network_id, self.member, '10.0.0.10')
        self.assertEqual(self.network(self.network_id)['connections'][str(self.member)], '10.0.0.10')
        self.assertEqual(effects['disconnect'], [self.member])

    def test_nobody_changes_someone_with_more_access(self):
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'addresses:modify': 'all', 'addresses:delete': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.change(self.member, self.organization, self.network_id, self.owner, '10.0.0.9')
        with self.assertRaises(PermissionError):
            self.admin.remove(self.member, self.organization, self.network_id, self.owner)

    def test_removing_the_primary_network_moves_the_primary(self):
        self.refused('only_network', self.admin.remove, self.owner, self.organization, self.network_id, self.member)
        office = self.create('10.1.0.0/24')
        self.organizations.join(self.member, self.organization, office)
        effects = self.admin.remove(self.owner, self.organization, self.network_id, self.member)

        self.assertNotIn(str(self.member), self.network(self.network_id)['connections'])
        self.assertEqual(self.account_networks(self.member), {str(office): dict(mode='assigned', primary=True)})
        self.assertEqual(effects['disconnect'], [self.member])


class NetworkAPITest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 52000), ('127.0.0.1', 52001)

    def setUp(self):
        super().setUp()
        self.server.panel, self.elsewhere = register_admin, []

    def pump(self, server, cipher, address, stack):
        for packet in stack.transmit():
            server.send_packet((cipher.encrypt(packet), address))
        while server.server.packets:
            packet, destination = server.server.packets.pop(0)
            # Control notices (for us or others) are kept for the test.
            if destination != address or Protocol.packet_type(packet) == Protocol.control:
                self.elsewhere.append((destination, packet))
            else: stack.receive(cipher.decrypt(packet))

    def logged(self, username='owner', address=None):
        channel = self.open(username, address or self.address)
        return channel, self.login(channel)[1]

    def test_writes_answer_before_the_panel_moves(self):
        channel, cookie = self.logged()
        cipher = self.vpn('member', self.member_address)[0]
        body = dict(network_id=str(self.network_id), router='10.0.0.200')

        self.assertEqual(self.request(channel, 'POST', '/api/networks/update', cookie, body, csrf=False)[0], 403)
        status, _, content = self.request(channel, 'POST', '/api/networks/update', cookie, body)
        self.assertEqual((status, content), (200, dict(router='10.0.0.200', network_range='10.0.0.0/24')))
        self.server.advance_bridges()

        self.assertEqual(self.server.bridges[self.network_id].ip_address, '10.0.0.200')
        # The routes and timers of the panel move with it.
        self.assertIs(self.server.bridges[self.network_id].server, self.bridge.server)
        notices = [Control.unpack(cipher.decrypt(packet, Protocol.control))['action']
                   for destination, packet in self.elsewhere if destination == self.member_address]
        self.assertEqual(notices, ['disconnected'])

    def test_refusals_carry_a_code(self):
        channel, cookie = self.logged()
        body = dict(network_id=str(self.network_id), max_address=1)
        status, _, content = self.request(channel, 'POST', '/api/networks/update', cookie, body)
        self.assertEqual((status, content['code'], content['used']), (400, 'limit_in_use', 2))
        status, _, content = self.request(channel, 'POST', '/api/networks/delete', cookie,
                                          dict(network_id=str(self.network_id)))
        self.assertEqual((status, content['code']), (400, 'last_network'))

    def test_a_new_network_starts_its_panel(self):
        channel, cookie = self.logged()
        status, _, content = self.request(channel, 'POST', '/api/networks/create', cookie,
                                          dict(network_range='10.1.0.0/24', name='Oficina'))
        self.assertEqual(status, 200)
        self.server.advance_bridges()
        bridge = self.server.bridges[ObjectId(content['network_id'])]
        self.assertEqual(bridge.ip_address, '10.1.0.254')
        self.assertIn(('GET', '/api/me'), bridge.server.routes)

    def test_deleting_asks_before_members_leave(self):
        channel, cookie = self.logged()
        office = self.request(channel, 'POST', '/api/networks/create', cookie,
                              dict(network_range='10.1.0.0/24'))[2]['network_id']
        self.request(channel, 'POST', '/api/assignments/add', cookie,
                     dict(network_id=office, email='member@example.com'))
        body = dict(network_id=office)
        status, _, content = self.request(channel, 'POST', '/api/networks/delete', cookie, body)
        # The member still has its primary network, so nobody leaves.
        self.assertEqual(status, 200)
        self.server.advance_bridges()
        self.assertNotIn(ObjectId(office), self.server.bridges)

        guest = self.account('guest')
        office = self.request(channel, 'POST', '/api/networks/create', cookie,
                              dict(network_range='10.2.0.0/24'))[2]['network_id']
        self.organizations.join(guest, self.organization, ObjectId(office))
        body = dict(network_id=office)
        status, _, content = self.request(channel, 'POST', '/api/networks/delete', cookie, body)
        self.assertEqual((status, [account['username'] for account in content['accounts']]), (409, ['guest']))
        body['confirm'] = True
        self.assertEqual(self.request(channel, 'POST', '/api/networks/delete', cookie, body)[0], 200)

    def test_assignments_list_their_actions(self):
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'addresses:view': 'all', 'addresses:modify': 'all'})
        self.vpn('owner', self.address)
        channel, cookie = self.logged('member', self.member_address)
        status, _, content = self.request(channel, 'GET', f'/api/assignments?network={self.network_id}', cookie)
        rows = {row['username']: row for row in content['rows']}
        self.assertEqual(content['total'], 2)
        more = self.request(channel, 'GET', f'/api/assignments?network={self.network_id}&offset=1&limit=x', cookie)[2]
        self.assertEqual(([row['username'] for row in more['rows']], more['total']), (['member'], 2))

        self.assertEqual(status, 200)
        self.assertEqual((rows['owner']['ip'], rows['owner']['primary'], rows['owner']['online']),
                         ('10.0.0.1', True, True))
        self.assertEqual(rows['owner']['actions'], dict(modify=False, delete=False))
        self.assertEqual(rows['member']['actions'], dict(modify=True, delete=False))
        other = self.request(channel, 'GET', f'/api/assignments?network={ObjectId()}', cookie)
        self.assertEqual(other[0], 404)

    def test_assignments_need_their_view_permission(self):
        channel, cookie = self.logged('member', self.member_address)
        path = f'/api/assignments?network={self.network_id}'
        self.assertEqual(self.request(channel, 'GET', path, cookie)[0], 403)


if __name__ == '__main__':
    unittest.main()
