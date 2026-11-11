import socket
import unittest
from unittest import mock

from connection.admin import diagnostics
from connection.egress import Egress
from connection import egress as egress_module
from connection.events import Events
from tests.panel import Panel

PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]


class EventsTest(unittest.TestCase):
    def test_events_are_kept_per_organization_newest_first(self):
        events = Events(limit=2)
        for number in range(3): events.record('org', 'INFO', 'connected', None, number=number)
        events.record(None, 'INFO', 'ignored')
        events.record('other', 'INFO', 'connected')
        shown = events.visible('org', lambda network_id: True)
        self.assertEqual([event['number'] for event in shown], [2, 1])
        self.assertEqual(events.visible('nobody', lambda network_id: True), [])
        # A session outside any organization leaves no trace.
        self.assertEqual(events.organizations.keys(), {'org', 'other'})

    def test_a_network_event_needs_that_network(self):
        events = Events()
        events.record('org', 'INFO', 'connected', 'net-a')
        events.record('org', 'WARN', 'member_kicked')
        visible = events.visible('org', lambda network_id: network_id == 'net-a')
        self.assertEqual([event['kind'] for event in visible], ['connected'])

    def test_the_internet_limit_is_reported_once_a_minute(self):
        notices = []
        egress = Egress(lambda *_: None, allowed=lambda address: True,
                        notify=lambda session, kind: notices.append(kind))
        session = object()
        udp = bytes.fromhex('450000220000400040110000') + socket.inet_aton('10.0.0.5') + socket.inet_aton('8.8.8.8')
        with mock.patch.object(egress_module, 'SESSION_FLOWS', 0):
            for port in range(3):
                egress.outbound(session, udp + bytes([0x9c, port, 0, 53, 0, 14, 0, 0]) + b'abcdef')
        self.assertEqual(notices, ['internet_limit'])


class DiagnosticsTest(unittest.TestCase):
    def test_requests_are_validated(self):
        self.assertEqual(diagnostics.request_of(dict(tool='dns', host=' Example.com ')), ('dns', 'example.com', None))
        self.assertEqual(diagnostics.request_of(dict(tool='tcp', host='example.com', port=443)),
                         ('tcp', 'example.com', 443))
        for body in (dict(tool='ping', host='example.com'), dict(tool='dns', host='a b'),
                     dict(tool='dns', host='-bad.com'), dict(tool='tcp', host='example.com', port=0),
                     dict(tool='tcp', host='example.com', port='80'), dict(tool='dns'), [], None):
            self.assertIsNone(diagnostics.request_of(body))

    def test_private_answers_stay_hidden(self):
        answers = PUBLIC + [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.10', 0))]
        with mock.patch.object(diagnostics.socket, 'getaddrinfo', return_value=answers):
            result = diagnostics.lookup('example.com')
        self.assertEqual((result['addresses'], result['hidden']), (['93.184.216.34'], 1))
        result = diagnostics.lookup('localhost')
        self.assertEqual(result['addresses'], [])
        self.assertGreater(result['hidden'], 0)
        self.assertEqual(diagnostics.lookup('nothing.invalid')['error'], 'not_found')

    def test_connections_only_reach_public_addresses(self):
        self.assertEqual(diagnostics.connect('127.0.0.1', 27017)['error'], 'not_public')
        with mock.patch.object(diagnostics.socket, 'getaddrinfo', return_value=PUBLIC):
            with mock.patch.object(diagnostics.socket, 'create_connection') as create:
                self.assertEqual(diagnostics.connect('example.com', 443)['address'], '93.184.216.34')
                create.assert_called_once_with(('93.184.216.34', 443), timeout=diagnostics.TIMEOUT)
                for failure, code in ((ConnectionRefusedError, 'refused'), (socket.timeout, 'timeout'),
                                      (OSError, 'unreachable')):
                    create.side_effect = failure
                    self.assertEqual(diagnostics.connect('example.com', 443)['error'], code)


class DiagnosticsAPITest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 54000), ('127.0.0.1', 54001)

    def pump(self, server, cipher, address, stack):
        # The kick notice for the other client is not part of this exchange.
        for packet in stack.transmit():
            server.send_packet((cipher.encrypt(packet), address))
        while server.server.packets:
            packet, destination = server.server.packets.pop(0)
            if destination == address: stack.receive(cipher.decrypt(packet))

    def logged(self, username='owner', address=None):
        channel = self.open(username, address or self.address)
        return channel, self.login(channel)[1]

    def kinds(self, channel, cookie):
        return [event['kind'] for event in self.request(channel, 'GET', '/api/logs', cookie)[2]['events']]

    def test_the_log_records_what_happened(self):
        channel, cookie = self.logged()
        self.vpn('member', self.member_address)
        self.request(channel, 'POST', '/api/sessions/kick', cookie, dict(account_id=str(self.member)))
        self.request(channel, 'POST', '/api/networks/update', cookie,
                     dict(network_id=str(self.network_id), name='Casa'))
        events = self.request(channel, 'GET', '/api/logs', cookie)[2]['events']

        self.assertEqual([event['kind'] for event in events],
                         ['network_updated', 'member_kicked', 'connected', 'panel_login', 'connected'])
        updated, kicked = events[0], events[1]
        self.assertEqual((updated['changes'], updated['by'], updated['network_id']),
                         (['name'], 'owner', str(self.network_id)))
        self.assertEqual((kicked['username'], kicked['by'], kicked['level']), ('member', 'owner', 'WARN'))

    def test_a_wrong_password_is_logged(self):
        channel = self.open('owner', self.address)
        self.request(channel, 'POST', '/api/login', None, dict(password='wrong'))
        cookie = self.login(channel)[1]
        failed = self.request(channel, 'GET', '/api/logs', cookie)[2]['events'][1]
        self.assertEqual((failed['kind'], failed['username'], failed['level']), ('login_failed', 'owner', 'WARN'))

    def test_each_viewer_sees_the_networks_it_may_watch(self):
        self.vpn('owner', self.address)
        self.server.events.record(self.organization, 'WARN', 'member_kicked', username='x')
        channel, cookie = self.logged('member', self.member_address)
        self.assertEqual(self.kinds(channel, cookie), [])
        self.organizations.grant(self.owner, self.organization, self.member, {'status:view': 'primary'})
        self.server.registry.remove_session(self.member)
        channel, cookie = self.logged('member', self.member_address)
        # Its own network's events, not the organization-wide ones.
        self.assertNotIn('member_kicked', self.kinds(channel, cookie))
        self.assertIn('connected', self.kinds(channel, cookie))

    def test_tests_run_from_the_server_with_permission(self):
        channel, cookie = self.logged()
        body = dict(tool='tcp', host='127.0.0.1', port=27017)
        self.assertEqual(self.request(channel, 'POST', '/api/diagnostics', cookie, body, csrf=False)[0], 403)
        status, _, content = self.request(channel, 'POST', '/api/diagnostics', cookie, body)
        self.assertEqual((status, content['error']), (200, 'not_public'))
        status, _, content = self.request(channel, 'POST', '/api/diagnostics', cookie, dict(tool='dns', host='localhost'))
        self.assertEqual((status, content['addresses']), (200, []))
        self.assertEqual(self.request(channel, 'POST', '/api/diagnostics', cookie, dict(tool='ping', host='x'))[0], 400)

        self.organizations.grant(self.owner, self.organization, self.member, {'status:view': 'primary'})
        channel, cookie = self.logged('member', self.member_address)
        self.assertEqual(self.request(channel, 'POST', '/api/diagnostics', cookie, body)[0], 403)


if __name__ == '__main__':
    unittest.main()
