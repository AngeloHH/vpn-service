import unittest

from connection.database.mongodb.organizations import Member
from connection.protocol import Control, Protocol
from tests.panel import Panel


class MembersTest(Panel, unittest.TestCase):
    owner_address, member_address = ('127.0.0.1', 51000), ('127.0.0.1', 51001)

    def setUp(self):
        super().setUp()
        self.elsewhere = []

    def pump(self, server, cipher, address, stack):
        # Packets for other clients (the kick notice) are kept for the test.
        for packet in stack.transmit():
            server.send_packet((cipher.encrypt(packet), address))
        while server.server.packets:
            packet, destination = server.server.packets.pop(0)
            if destination != address: self.elsewhere.append(packet)
            else: stack.receive(cipher.decrypt(packet))

    def notices(self, cipher):
        return [Control.unpack(cipher.decrypt(packet, Protocol.control))['action']
                for packet in self.elsewhere]

    def logged(self, username, address):
        channel = self.open(username, address)
        return channel, self.login(channel)[1]

    def stored(self, account_id):
        return Member(self.collections['members']).get(organization_id=self.organization,
                                                       account_id=account_id)

    def test_ports_list_connected_members_oldest_first(self):
        channel, cookie = self.logged('owner', self.owner_address)
        self.vpn('member', self.member_address)
        # The member connected later but has been connected longer: it keeps the first port.
        self.server.registry.get_account(self.member).connected_at -= 600
        status, _, content = self.request(channel, 'GET', '/api/members/ports', cookie)
        self.assertEqual(status, 200)
        self.assertEqual([row['username'] for row in content['rows']], ['member', 'owner'])
        self.assertEqual(set(content['rows'][0]), {'id', 'username', 'email', 'ip', 'networks', 'connected_for'})
        # Someone without members:view sees nobody.
        member_channel, member_cookie = self.logged('member', self.member_address)
        self.assertEqual(self.request(member_channel, 'GET', '/api/members/ports', member_cookie)[2]['rows'], [])

    def reconnect(self, username, address):
        # Permissions load on connect, so a changed member logs in again.
        self.server.registry.remove_session(self.server.registry.get_account(
            self.owner if username == 'owner' else self.member).account_id)
        return self.logged(username, address)

    def test_connected_members_are_listed_with_their_traffic(self):
        channel, cookie = self.logged('owner', self.owner_address)
        self.vpn('member', self.member_address)
        session = self.server.registry.get_account(self.member)
        session.rates, session.loss, session.sent, session.received = (12.5, 3.0), 2.0, 700, 300

        status, _, content = self.request(channel, 'GET', '/api/members', cookie)
        rows = {row['username']: row for row in content['rows']}

        self.assertEqual(status, 200)
        self.assertEqual((content['total'], content['page'], content['size']), (2, 1, 25))
        member = rows['member']
        self.assertEqual(member['id'], str(self.member))
        self.assertEqual(member['email'], 'member@example.com')
        self.assertEqual(member['networks'], [str(self.network_id)])
        self.assertEqual((member['down'], member['up'], member['loss'], member['total']),
                         (12.5, 3.0, 2.0, 1000))
        self.assertTrue(member['online'] and not member['blocked'])
        self.assertEqual(member['actions'], dict(block=True, kick=True))
        # Nobody acts on their own session.
        self.assertEqual(rows['owner']['actions'], dict(block=False, kick=False))

    def test_members_need_their_view_permission(self):
        self.vpn('owner', self.owner_address)
        channel, cookie = self.logged('member', self.member_address)
        content = self.request(channel, 'GET', '/api/members', cookie)[2]
        self.assertEqual(content['rows'], [])

        guest = self.account('guest')
        self.organizations.join(guest, self.organization, self.network_id)
        self.organizations.set_blocked(self.owner, self.organization, guest, True)
        blocked = self.request(channel, 'GET', '/api/members?filter=blocked', cookie)[2]
        self.assertEqual(blocked['rows'], [])

        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'members:view': 'all', 'sessions:delete': 'all'})
        channel, cookie = self.reconnect('member', self.member_address)
        rows = self.request(channel, 'GET', '/api/members', cookie)[2]['rows']
        blocked = self.request(channel, 'GET', '/api/members?filter=blocked', cookie)[2]
        self.assertEqual([row['username'] for row in blocked['rows']], ['guest'])
        owner = next(row for row in rows if row['username'] == 'owner')
        # The administrator has more access, so the member cannot act on them.
        self.assertEqual(owner['actions'], dict(block=False, kick=False))
        body = dict(account_id=str(self.owner))
        self.assertEqual(self.request(channel, 'POST', '/api/sessions/kick', cookie, body)[0], 403)
        self.assertIsNotNone(self.server.registry.get_account(self.owner))

    def test_pages_search_and_sizes(self):
        channel, cookie = self.logged('owner', self.owner_address)
        self.vpn('member', self.member_address)

        def page(query):
            return self.request(channel, 'GET', f'/api/members?{query}', cookie)[2]

        self.assertEqual(page('size=7')['size'], 25)
        self.assertEqual(page('size=50')['size'], 50)
        self.assertEqual(page('page=2')['rows'], [])
        self.assertEqual([row['username'] for row in page('q=MEMBER@')['rows']], ['member'])
        self.assertEqual(page('network=000000000000000000000000')['total'], 0)

    def test_a_kicked_member_is_disconnected(self):
        channel, cookie = self.logged('owner', self.owner_address)
        cipher = self.vpn('member', self.member_address)[0]
        body = dict(account_id=str(self.member))

        self.assertEqual(self.request(channel, 'POST', '/api/sessions/kick', cookie, body,
                                      csrf=False)[0], 403)
        self.assertIsNotNone(self.server.registry.get_account(self.member))
        self.assertEqual(self.request(channel, 'POST', '/api/sessions/kick', cookie, body)[0], 204)
        self.assertIsNone(self.server.registry.get_account(self.member))
        self.assertEqual(self.notices(cipher), ['kicked'])
        self.assertEqual(self.request(channel, 'POST', '/api/sessions/kick', cookie, body)[0], 404)
        own = dict(account_id=str(self.owner))
        self.assertEqual(self.request(channel, 'POST', '/api/sessions/kick', cookie, own)[0], 400)

    def test_a_blocked_member_is_kicked_and_listed_offline(self):
        channel, cookie = self.logged('owner', self.owner_address)
        cipher = self.vpn('member', self.member_address)[0]
        body = dict(account_id=str(self.member), blocked=True)

        self.assertEqual(self.request(channel, 'POST', '/api/members/block', cookie, body)[0], 204)
        self.assertTrue(self.stored(self.member)['blocked'])
        self.assertIsNone(self.server.registry.get_account(self.member))
        self.assertEqual(self.notices(cipher), ['kicked'])
        with self.assertRaises(KeyError):
            self.vpn('member', self.member_address)

        content = self.request(channel, 'GET', '/api/members?filter=blocked', cookie)[2]
        self.assertEqual([(row['username'], row['online'], row['blocked'], row['networks'])
                          for row in content['rows']],
                         [('member', False, True, [str(self.network_id)])])
        self.assertTrue(content['rows'][0]['actions']['block'])

        body['blocked'] = False
        self.assertEqual(self.request(channel, 'POST', '/api/members/block', cookie, body)[0], 204)
        self.assertFalse(self.stored(self.member)['blocked'])
        self.vpn('member', self.member_address)
        self.assertIsNotNone(self.server.registry.get_account(self.member))

    def test_blocking_needs_permission_and_more_access(self):
        self.vpn('owner', self.owner_address)
        channel, cookie = self.logged('member', self.member_address)
        body = dict(account_id=str(self.owner), blocked=True)
        self.assertEqual(self.request(channel, 'POST', '/api/members/block', cookie, body)[0], 403)

        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'members:modify': 'all'})
        channel, cookie = self.reconnect('member', self.member_address)
        self.assertEqual(self.request(channel, 'POST', '/api/members/block', cookie, body)[0], 403)
        self.assertFalse(self.stored(self.owner).get('blocked'))
        own = dict(account_id=str(self.member), blocked=True)
        self.assertEqual(self.request(channel, 'POST', '/api/members/block', cookie, own)[0], 400)
        invalid = dict(account_id='nope', blocked=True)
        self.assertEqual(self.request(channel, 'POST', '/api/members/block', cookie, invalid)[0], 400)


if __name__ == '__main__':
    unittest.main()
