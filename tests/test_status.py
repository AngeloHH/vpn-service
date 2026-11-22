import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bson import ObjectId
from tcp_sansio import TCPStack

from connection import __main__ as cli, system
from connection.admin import register_admin
from connection.organizations import Organizations
from connection.permissions import Permissions
from connection.vpn_service import VPNServer
from tests import test_vpn_service as tunnel
from tests.test_organizations import Collection
from tests.panel import PANEL, Panel


class SystemTest(unittest.TestCase):
    def test_the_model_is_a_hash_of_the_project_and_its_version(self):
        self.assertEqual(system.MODEL, 'F8D4B5 v0.1.0')

    def test_linux_reports_the_hottest_sensor(self):
        sensors = dict(cpu=[SimpleNamespace(current=48.0), SimpleNamespace(current=61.5)])
        with mock.patch.object(system.platform, 'system', return_value='Linux'), \
                mock.patch.object(system.psutil, 'sensors_temperatures',
                                  return_value=sensors, create=True):
            self.assertEqual(system.temperature(), 61.5)
        with mock.patch.object(system.platform, 'system', return_value='Linux'), \
                mock.patch.object(system.psutil, 'sensors_temperatures',
                                  return_value={}, create=True):
            self.assertIsNone(system.temperature())

    def test_windows_converts_tenths_of_kelvin(self):
        output = SimpleNamespace(stdout='3132\r\n3232\r\n')
        with mock.patch.object(system.platform, 'system', return_value='Windows'), \
                mock.patch.object(system.subprocess, 'run', return_value=output):
            self.assertAlmostEqual(system.temperature(), 50.05, delta=0.1)
        with mock.patch.object(system.platform, 'system', return_value='Windows'), \
                mock.patch.object(system.subprocess, 'run', side_effect=OSError):
            self.assertIsNone(system.temperature())

    def test_other_systems_report_no_temperature(self):
        with mock.patch.object(system.platform, 'system', return_value='Darwin'):
            self.assertIsNone(system.temperature())

    def test_metrics_belong_to_the_vpn_process(self):
        metrics = system.ProcessMetrics()
        self.assertEqual(metrics.process.pid, os.getpid())
        with mock.patch.object(system, 'temperature', return_value=None):
            sample = metrics.sample()
        self.assertGreaterEqual(sample['cpu'], 0)
        self.assertGreater(sample['memory'], 0)
        self.assertGreater(sample['memory_percent'], 0)


class StatusTest(Panel, unittest.TestCase):
    def logged(self, username, address):
        channel = self.open(username, address)
        return channel, self.login(channel)[1]

    def test_the_status_crosses_the_encrypted_tunnel(self):
        channel, cookie = self.logged('owner', ('127.0.0.1', 50000))
        status, _, content = self.request(channel, 'GET', '/api/status', cookie)
        self.assertEqual(status, 200)
        self.assertEqual(content['model'], 'F8D4B5 v0.1.0')
        self.assertEqual(content['firmware'], '0.1.0')
        self.assertEqual(content['mode'], 'local')
        self.assertEqual(len(content['serial']), 10)
        self.assertGreaterEqual(content['uptime'], 100)
        self.assertEqual(content['sessions'], 1)
        self.assertEqual((content['cpu'], content['memory'], content['temperature']),
                         (1.5, 1024, None))
        time.strptime(content['time'], '%Y-%m-%d %H:%M:%S')
        self.assertRegex(content['timezone']['offset'], r'^[+-]\d{4}$')
        self.assertEqual(content['timezone']['name'], time.strftime('%Z'))

    def test_the_status_needs_its_permission(self):
        address = '127.0.0.1', 50001
        channel, cookie = self.logged('member', address)
        self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[0], 403)
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'status:view': 'all'})
        # Permissions load on connect, so the member reconnects to receive them.
        channel, cookie = self.logged('member', address)
        self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[0], 200)

    def test_a_foreign_host_is_rejected(self):
        channel, cookie = self.logged('owner', ('127.0.0.1', 50000))
        status = self.request(channel, 'GET', '/api/status', cookie, host='evil.example')[0]
        self.assertEqual(status, 403)

    def test_sessions_are_counted_per_organization(self):
        outsider = self.account('outsider')
        other = self.organizations.create(outsider, network_range='10.9.0.0/24')
        other_network = next(network['_id'] for network in self.collections['networks'].documents
                             if network['organization_id'] == other)
        self.vpn('outsider', ('127.0.0.1', 50002), other_network)
        channel, cookie = self.logged('owner', ('127.0.0.1', 50000))
        self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[2]['sessions'], 1)

    def test_one_connection_serves_several_requests(self):
        channel, cookie = self.logged('owner', ('127.0.0.1', 50000))
        for _ in range(2):
            self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[0], 200)
        self.assertFalse(channel[2].eof)

    def test_status_events_flow_until_access_is_lost(self):
        channel, cookie = self.logged('owner', ('127.0.0.1', 50000))
        request = f'GET /api/events HTTP/1.1\r\nHost: {PANEL}\r\nCookie: {cookie}\r\n\r\n'
        channel[2].send(request.encode())
        first = self.exchange(channel, lambda data: data.endswith(b'}\n\n\r\n'))
        self.assertIn(b'Content-Type: text/event-stream', first)
        self.assertIn(b'event: status\ndata: {', first)

        self.server.metrics = dict(self.server.metrics, cpu=7.5)
        self.bridge.server.run_timers(time.monotonic() + 5)
        self.server.advance_bridges()
        self.assertIn(b'"cpu":7.5', self.exchange(channel, lambda data: b'}\n\n' in data))

        session = self.server.registry.get_route(self.network_id, '10.0.0.1')
        session.permissions = Permissions()
        self.bridge.server.run_timers(time.monotonic() + 10)
        self.server.advance_bridges()
        self.assertIn(b'0\r\n\r\n', self.exchange(channel, lambda data: b'0\r\n\r\n' in data))


class ServeTest(unittest.TestCase):
    def run_cli(self, *arguments):
        collections = dict(networks=Collection())
        mongo = tunnel.MongoClient(tunnel.Database(collections))
        with mock.patch.object(cli, 'MongoClient', return_value=mongo), \
                mock.patch.object(VPNServer, 'run_server'), \
                mock.patch('builtins.print'):
            server = cli.main(['serve', '--key', str(self.key), '--workers', '1', *arguments])
        server.close()
        return server

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.key = Path(self.directory.name) / 'server.key'

    def tearDown(self): self.directory.cleanup()

    def test_the_key_is_created_once_and_reused(self):
        first = self.run_cli()
        self.assertEqual(self.key.read_text(), first.secret)
        if os.name == 'posix': self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.run_cli().secret, first.secret)

    def test_the_mode_is_chosen_from_the_command_line(self):
        self.assertFalse(self.run_cli().public)
        self.assertTrue(self.run_cli('--public').public)

    def test_the_internet_is_closed_unless_the_server_opens_it(self):
        self.assertFalse(self.run_cli().internet)
        self.assertTrue(self.run_cli('--internet').internet)


if __name__ == '__main__': unittest.main()
