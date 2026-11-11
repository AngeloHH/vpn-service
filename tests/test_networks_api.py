import json
import threading
import time
import unittest
from unittest import mock

from connection.database.mongodb import Network
from tests.panel import PANEL, Panel


class NetworksAPITest(Panel, unittest.TestCase):
    address = '127.0.0.1', 50000

    def logged(self, username, address=None):
        channel = self.open(username, address or self.address)
        return channel, self.login(channel)[1]

    def networks(self, username, address=None):
        channel, cookie = self.logged(username, address)
        status, _, content = self.request(channel, 'GET', '/api/networks', cookie)
        self.assertEqual(status, 200)
        return content['networks']

    def add_network(self, network_range, name=None):
        network = Network(self.collections['networks'])
        network.create(network_range, 253, self.organization, name)
        return network.id

    def test_each_network_reports_its_real_fields(self):
        network, = self.networks('owner')
        self.assertEqual(network, dict(
            id=str(self.network_id), name=None, number=1, network_range='10.0.0.0/24',
            subnet_mask='255.255.255.0', router=PANEL, members=2, used=3, capacity=253,
            max_address=253, assigned=2, internet=False, dns=[], your_ip='10.0.0.1', primary=True, can=dict(
                modify=True, delete=True, view_addresses=True, add_address=True,
                modify_address=True, delete_address=True)))

    def test_only_networks_of_the_organization_are_listed(self):
        self.organizations.create(self.account('outsider'), network_range='10.9.0.0/24')
        office = self.add_network('10.1.0.0/24', 'Oficina')
        networks = self.networks('owner')
        self.assertEqual([network['id'] for network in networks],
                         [str(self.network_id), str(office)])
        self.assertEqual((networks[1]['name'], networks[1]['your_ip']), ('Oficina', None))

    def test_the_view_permission_and_its_scope_filter_the_list(self):
        self.add_network('10.1.0.0/24', 'Oficina')
        self.assertEqual(self.networks('member', ('127.0.0.1', 50001)), [])
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'networks:view': 'primary'})
        primary = self.networks('member', ('127.0.0.1', 50001))
        self.assertEqual([network['id'] for network in primary], [str(self.network_id)])
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'networks:view': 'all'})
        self.assertEqual(len(self.networks('member', ('127.0.0.1', 50001))), 2)

    def test_the_database_is_read_off_the_packet_loop(self):
        threads, find = [], self.collections['networks'].find

        def record(query):
            threads.append(threading.current_thread())
            return find(query)

        channel, cookie = self.logged('owner')
        with mock.patch.object(self.collections['networks'], 'find', side_effect=record):
            self.request(channel, 'GET', '/api/networks', cookie)
        self.assertTrue(threads)
        self.assertNotIn(threading.main_thread(), threads)

    def test_the_status_counts_sessions_per_network(self):
        self.vpn('member', ('127.0.0.1', 50001))
        online = self.server.status(self.organization)['online']
        self.assertEqual(online, {str(self.network_id): 1})

    def test_open_panels_receive_new_networks(self):
        channel, cookie = self.logged('owner')
        request = f'GET /api/events HTTP/1.1\r\nHost: {PANEL}\r\nCookie: {cookie}\r\n\r\n'
        channel[2].send(request.encode())
        first = self.exchange(channel, lambda data: b'event: networks' in data and data.endswith(b'\n\n\r\n'))
        self.assertEqual(len(self.events(first, 'networks')[-1]), 1)

        self.add_network('10.1.0.0/24', 'Oficina')
        self.bridge.server.run_timers(time.monotonic() + 6)
        received = self.exchange(channel, lambda data: b'Oficina' in data)
        self.assertEqual([network['name'] for network in self.events(received, 'networks')[-1]],
                         [None, 'Oficina'])

    @staticmethod
    def events(data: bytes, name: str) -> list:
        marker, found = f'event: {name}\ndata: '.encode(), []
        for part in data.split(marker)[1:]:
            found.append(json.loads(part.split(b'\n', 1)[0]))
        return found


if __name__ == '__main__': unittest.main()
