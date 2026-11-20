import socket
import unittest
from unittest import mock

from bson import ObjectId
from scapy.layers.inet import IP
from scapy.packet import Raw

from connection import utils
from connection.database.mongodb import Account, Network
from connection.protocol import Control, Protocol
from connection.vpn_service import VPNClient, VPNServer
from tests import RECORD
from tests import test_vpn_service as tunnel


class ClientSocket:
    # Delivers client packets to the server and can lose its replies.
    def __init__(self, server, address, lost: int = 0):
        self.server, self.address, self.lost, self.inbox = server, address, lost, []

    def sendto(self, packet, address):
        self.server.receive_control((packet, self.address))
        replies, self.server.server.packets = self.server.server.packets, []
        if self.lost: self.lost -= 1
        else: self.inbox += [packet for packet, _ in replies]

    def recvfrom(self, size):
        if not self.inbox: raise socket.timeout()
        return self.inbox.pop(0), ('127.0.0.1', 5732)

    def gettimeout(self): return None
    def settimeout(self, timeout): pass


class ControlTest(unittest.TestCase):
    login = tunnel.VPNServiceTest.login
    control = tunnel.VPNServiceTest.control
    address = '127.0.0.1', 50000

    def setUp(self):
        self.account_id = ObjectId()
        self.network_a, self.network_b, self.routed = ObjectId(), ObjectId(), ObjectId()
        accounts = tunnel.Collection([dict(
            _id=self.account_id, username='username',
            srp=RECORD, networks={}
        )])
        network = lambda _id, network_range: dict(
            _id=_id, subnet_mask='255.255.255.0', network_range=network_range,
            max_address=10, connections={}, routes={}
        )
        networks = tunnel.Collection([
            network(self.network_a, '10.10.0.0/24'),
            network(self.network_b, '10.20.0.0/24'),
            network(self.routed, '10.30.0.0/24')
        ])
        self.collections = dict(
            accounts=accounts, networks=networks, connections=tunnel.Collection()
        )
        account = Account(accounts, self.account_id)
        Network(networks, self.network_a).to_network(account, primary=True)
        Network(networks, self.network_b).to_network(account)
        Network(networks, self.routed).to_network(
            account, mode='routed', source_network=self.network_a
        )
        address = lambda _id: Network(networks, _id).get()['connections'][str(self.account_id)]
        self.ip_a, self.ip_b = address(self.network_a), address(self.network_b)
        mongo = tunnel.MongoClient(tunnel.Database(self.collections))
        self.server = VPNServer(mongo, 'database')
        self.server.server.close()
        self.server.server = tunnel.Socket()

    def operations(self):
        return sum(collection.operations for collection in self.collections.values())

    def connect(self, cipher, network_id, **kwargs):
        return self.control(self.server, cipher, self.address, action='connect',
                            network_id=network_id.__str__(), **kwargs)

    def test_a_login_routes_nothing_until_a_network_is_selected(self):
        cipher = self.login(self.server, self.address)
        session = self.server.registry.get_session(cipher.session_id)
        packet = bytes(IP(src='10.10.0.1', dst='10.10.0.1') / Raw(b'data'))
        self.server.send_packet((cipher.encrypt(packet), self.address))

        self.assertEqual(session.networks, {})
        notice = self.server.server.packets.pop()[0]
        message = Control.unpack(cipher.decrypt(notice, Protocol.control))
        self.assertEqual(message, dict(action=Control.disconnected))

    def test_the_list_groups_routed_networks_with_their_identity(self):
        cipher = self.login(self.server, self.address)
        options = self.control(self.server, cipher, self.address, action='list')['networks']
        options = {option['network_id']: option for option in options}

        self.assertEqual(set(options), {str(self.network_a), str(self.network_b)})
        self.assertEqual(options[str(self.network_a)]['routed'], [str(self.routed)])
        self.assertTrue(options[str(self.network_a)]['default'])
        self.assertFalse(options[str(self.network_b)]['default'])

    def test_connect_activates_the_identity_and_its_routed_networks(self):
        cipher = self.login(self.server, self.address)
        configuration = self.connect(cipher, self.network_a)['configuration']
        session = self.server.registry.get_session(cipher.session_id)

        self.assertEqual({(network['network_id'], network['ip_address'])
                          for network in configuration},
                         {(str(self.network_a), self.ip_a),
                          (str(self.routed), self.ip_a)})
        self.assertIs(self.server.registry.get_route(self.network_a, self.ip_a), session)
        self.assertIs(self.server.registry.get_route(self.routed, self.ip_a), session)
        self.assertIsNone(self.server.registry.get_route(self.network_b, self.ip_b))

    def test_switching_releases_the_previous_network(self):
        cipher = self.login(self.server, self.address)
        self.connect(cipher, self.network_a)
        configuration = self.connect(cipher, self.network_b)['configuration']

        self.assertEqual([network['network_id'] for network in configuration],
                         [str(self.network_b)])
        self.assertIsNone(self.server.registry.get_route(self.network_a, self.ip_a))
        self.assertIsNone(self.server.registry.get_route(self.routed, self.ip_a))

    def test_an_unavailable_network_keeps_the_current_routes(self):
        cipher = self.login(self.server, self.address)
        self.connect(cipher, self.network_a)
        for network_id in (ObjectId(), 'invalid'):
            reply = self.connect(cipher, network_id)
            self.assertEqual((reply['error'], reply['message']), ('network_unavailable', 'The network is not available'))
        session = self.server.registry.get_session(cipher.session_id)
        self.assertIs(self.server.registry.get_route(self.network_a, self.ip_a), session)

    def test_a_retransmitted_request_is_not_applied_twice(self):
        cipher = self.login(self.server, self.address)
        first = self.connect(cipher, self.network_a, request=5)
        operations = self.operations()
        repeated = self.connect(cipher, self.network_a, request=5)

        self.assertEqual(repeated, first)
        self.assertEqual(self.operations(), operations)
        stale = Control.pack(dict(request=4, action='connect',
                                  network_id=str(self.network_b)))
        self.server.receive_control((cipher.encrypt(stale, Protocol.control), self.address))
        self.assertEqual(self.server.server.packets, [])

    def test_a_change_is_written_before_the_session_is_disconnected(self):
        cipher = self.login(self.server, self.address)
        self.connect(cipher, self.network_a)
        network = Network(self.collections['networks'], self.network_a)
        calls = []

        def change():
            connections = {str(self.account_id): '10.10.0.7'}
            calls.append(bool(self.server.registry.get_route(self.network_a, self.ip_a)))
            return network.update(connections=connections)

        self.server.change_account(self.account_id, change)
        notice = self.server.server.packets.pop()[0]
        message = Control.unpack(cipher.decrypt(notice, Protocol.control))

        self.assertEqual(calls, [True])
        self.assertEqual(message, dict(action=Control.disconnected))
        self.assertIsNone(self.server.registry.get_route(self.network_a, self.ip_a))
        configuration = self.connect(cipher, self.network_a)['configuration']
        self.assertEqual(configuration[0]['ip_address'], '10.10.0.7')

    def test_a_failed_change_keeps_the_session_connected(self):
        cipher = self.login(self.server, self.address)
        self.connect(cipher, self.network_a)

        def change(): raise RuntimeError('write failed')

        with self.assertRaises(RuntimeError):
            self.server.change_account(self.account_id, change)
        session = self.server.registry.get_session(cipher.session_id)
        self.assertIs(self.server.registry.get_route(self.network_a, self.ip_a), session)
        self.assertEqual(self.server.server.packets, [])

    def test_the_client_retries_a_lost_reply_without_repeating_it(self):
        client = VPNClient(('127.0.0.1', 5732))
        client.cipher = self.login(self.server, self.address)
        client.socket_server.close()
        client.socket_server = ClientSocket(self.server, self.address, lost=1)
        options = client.list_networks()
        default = next(option for option in options if option['default'])
        operations = self.operations()

        client.socket_server.lost = 1
        networks = client.select_network(default['network_id'])
        self.assertEqual(networks[0]['ip_address'], self.ip_a)
        self.assertEqual(client.network_id, str(self.network_a))
        # A single connect writes the connection record once despite the retry.
        connections = self.collections['connections'].documents
        self.assertEqual(len(connections), 1)
        self.assertGreater(self.operations(), operations)
        for command in client.commands: command.close()


    def test_a_deleted_network_reconnects_to_the_primary_one(self):
        client = VPNClient(('127.0.0.1', 5732))
        client.cipher = self.login(self.server, self.address)
        client.socket_server.close()
        client.socket_server = ClientSocket(self.server, self.address)
        client.select_network(str(self.network_b))
        # The server removed network B from the account, as a deletion does.
        account = Account(self.collections['accounts'], self.account_id)
        networks = account.get()['networks']
        networks.pop(str(self.network_b))
        account.update(networks=networks)

        client.reconnect()
        self.assertEqual(client.network_id, str(self.network_a))
        self.assertEqual(client.networks[0]['ip_address'], self.ip_a)
        for command in client.commands: command.close()

    def test_a_kicked_client_stops_instead_of_reconnecting(self):
        client = VPNClient(('127.0.0.1', 5732))
        client.cipher = self.login(self.server, self.address)
        self.server.kick(self.account_id)
        self.assertIsNone(self.server.registry.get_account(self.account_id))

        message = client.receive(self.server.server.packets.pop()[0])
        self.assertEqual(message['action'], 'kicked')
        self.assertTrue(client.kicked)
        self.assertFalse(client.disconnected)
        client.socket_server.close()
        for command in client.commands: command.close()


class RemoveNetworksTest(unittest.TestCase):
    def test_removal_mirrors_the_configuration(self):
        networks = [
            dict(mode='assigned', primary=True, ip_address='10.10.0.2',
                 subnet_mask='255.255.255.0', network_range='10.10.0.0/24',
                 routes=['10.10.0.9/32']),
            dict(mode='assigned', primary=False, ip_address='10.20.0.2',
                 subnet_mask='255.255.255.0', network_range='10.20.0.0/24',
                 routes=[])
        ]
        with mock.patch.object(utils.platform, 'system', return_value='Linux'), \
                mock.patch.object(utils.subprocess, 'run') as run:
            utils.remove_networks('vpn0', networks)
        commands = [call.args[0] for call in run.call_args_list]

        self.assertEqual(commands, [
            ['ip', 'route', 'del', '10.10.0.9/32', 'dev', 'vpn0'],
            ['ip', 'route', 'del', '10.10.0.0/24', 'dev', 'vpn0'],
            ['ip', 'route', 'del', '10.20.0.0/24', 'dev', 'vpn0'],
            ['ip', 'address', 'del', '10.20.0.2/24', 'dev', 'vpn0']
        ])



class InternetRoutesTest(unittest.TestCase):
    networks = [dict(mode='assigned', primary=True, ip_address='10.10.0.2', subnet_mask='255.255.255.0',
                     network_range='10.10.0.0/24', routes=[], internet=True)]

    def commands(self, system, operation, output='', server='203.0.113.7', networks=None):
        result = mock.Mock(stdout=output)
        with mock.patch.object(utils.platform, 'system', return_value=system), \
                mock.patch.object(utils.subprocess, 'run', return_value=result) as run:
            operation('vpn0', networks or self.networks, server)
        return [call.args[0] for call in run.call_args_list]

    def test_linux_keeps_the_server_on_its_gateway(self):
        output = '203.0.113.7 via 192.168.1.1 dev eth0 src 192.168.1.20 uid 0'
        commands = self.commands('Linux', utils.configure_networks, output)
        self.assertEqual(commands[1:], [
            ['ip', 'route', 'get', '203.0.113.7'],
            ['ip', 'route', 'replace', '203.0.113.7/32', 'via', '192.168.1.1', 'dev', 'eth0'],
            ['ip', 'route', 'replace', '0.0.0.0/1', 'dev', 'vpn0', 'src', '10.10.0.2'],
            ['ip', 'route', 'replace', '128.0.0.0/1', 'dev', 'vpn0', 'src', '10.10.0.2']])
        # A server on the same LAN has no gateway.
        self.assertIn(['ip', 'route', 'replace', '192.168.1.9/32', 'dev', 'eth0'],
                      self.commands('Linux', utils.configure_networks, '192.168.1.9 dev eth0', '192.168.1.9'))
        self.assertEqual(self.commands('Linux', utils.remove_networks)[:3], [
            ['ip', 'route', 'del', '0.0.0.0/1', 'dev', 'vpn0'],
            ['ip', 'route', 'del', '128.0.0.0/1', 'dev', 'vpn0'],
            ['ip', 'route', 'del', '203.0.113.7/32']])

    def test_windows_and_macos_use_their_own_tools(self):
        commands = self.commands('Windows', utils.configure_networks)
        self.assertEqual(commands[1][:3], ['powershell', '-NoProfile', '-Command'])
        self.assertIn("Find-NetRoute -RemoteIPAddress '203.0.113.7'", commands[1][3])
        self.assertEqual(commands[2:], [
            ['route', 'add', '0.0.0.0', 'mask', '128.0.0.0', '10.10.0.2', 'metric', '1'],
            ['route', 'add', '128.0.0.0', 'mask', '128.0.0.0', '10.10.0.2', 'metric', '1']])
        removal = self.commands('Windows', utils.remove_networks)
        self.assertIn("Remove-NetRoute -DestinationPrefix '203.0.113.7/32'", removal[2][3])
        output = '   route to: 203.0.113.7\n    gateway: 192.168.1.1\n  interface: en0\n'
        commands = self.commands('Darwin', utils.configure_networks, output)
        self.assertEqual(commands[2], ['route', '-n', 'add', '-host', '203.0.113.7', '192.168.1.1'])

    def test_only_networks_with_internet_and_remote_servers_change_the_default(self):
        closed = [dict(self.networks[0], internet=False)]
        self.assertEqual(len(self.commands('Linux', utils.configure_networks, networks=closed)), 1)
        self.assertEqual(len(self.commands('Linux', utils.remove_networks, networks=closed)), 1)
        # A server on this same machine needs no route of its own.
        local = self.commands('Linux', utils.configure_networks, server='127.0.0.1')
        self.assertEqual([command[3] for command in local[1:]], ['0.0.0.0/1', '128.0.0.0/1'])



class DNSTest(unittest.TestCase):
    network = dict(mode='assigned', primary=True, ip_address='10.10.0.2', subnet_mask='255.255.255.0',
                   network_range='10.10.0.0/24', routes=[], dns=['10.10.0.53', '1.1.1.1'])

    def commands(self, system, operation, network=None, side_effect=None):
        with mock.patch.object(utils.platform, 'system', return_value=system), \
                mock.patch.object(utils.subprocess, 'run', side_effect=side_effect) as run:
            operation('vpn0', [network or self.network])
        return [call.args[0] for call in run.call_args_list]

    def test_the_card_gets_the_network_dns(self):
        windows = self.commands('Windows', utils.configure_networks)[1:]
        self.assertEqual(windows, [
            ['netsh', 'interface', 'ipv4', 'set', 'dnsservers', 'name=vpn0', 'source=static',
             'address=10.10.0.53', 'register=none', 'validate=no'],
            ['netsh', 'interface', 'ipv4', 'add', 'dnsservers', 'name=vpn0', 'address=1.1.1.1',
             'index=2', 'validate=no']])
        self.assertEqual(self.commands('Linux', utils.configure_networks)[1:],
                         [['resolvectl', 'dns', 'vpn0', '10.10.0.53', '1.1.1.1']])
        # With internet through the VPN, every name goes to these servers.
        internet = dict(self.network, internet=True)
        self.assertIn(['resolvectl', 'domain', 'vpn0', '~.'],
                      self.commands('Linux', lambda *arguments: utils.configure_networks(*arguments), internet))

    def test_the_dns_is_removed_with_the_networks(self):
        self.assertEqual(self.commands('Linux', utils.remove_networks)[0], ['resolvectl', 'revert', 'vpn0'])
        self.assertIn('address=none', self.commands('Windows', utils.remove_networks)[0])
        self.assertEqual(self.commands('Linux', utils.configure_networks, dict(self.network, dns=[]))[1:], [])
        self.assertEqual(len(self.commands('Linux', utils.remove_networks, dict(self.network, dns=[]))), 1)

    def test_a_missing_resolver_does_not_break_the_connection(self):
        def missing(command, **_):
            if command[0] == 'resolvectl': raise FileNotFoundError('resolvectl')
        with self.assertLogs(utils.logger, 'WARNING'):
            self.commands('Linux', utils.configure_networks, side_effect=missing)
        with self.assertLogs(utils.logger, 'WARNING'):
            self.assertEqual(self.commands('Darwin', utils.configure_networks)[1:], [])
        self.commands('Linux', utils.remove_networks, side_effect=missing)


if __name__ == '__main__': unittest.main()
