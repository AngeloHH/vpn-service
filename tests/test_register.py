import argparse
import socket
import unittest
from unittest import mock

from connection import __main__ as cli, srp
from connection.attempts import Attempts
from connection.errors import VPNError
from connection.organizations import Organizations
from connection.protocol import ClientHandshake, Protocol
from connection.vpn_service import ORGANIZATIONS, VPNClient, VPNServer
from tests import PASSWORD
from tests import test_vpn_service as tunnel
from tests.test_organizations import Collection


class ServerSocket:
    # The client's socket delivers straight into the server, which answers at once.
    def __init__(self, server, address):
        self.server, self.address, self.replies = server, address, []

    def sendto(self, packet, address):
        self.server.server.packets.clear()
        packet_type = Protocol.packet_type(packet)
        if packet_type == Protocol.control: self.server.receive_control((packet, self.address))
        else: self.server.receive_handshake((packet, self.address))
        self.replies += [reply for reply, _ in self.server.server.packets]
        self.server.server.packets.clear()

    def recvfrom(self, size):
        # Nothing left: like a silent server, the wait times out.
        if not self.replies: raise socket.timeout()
        return self.replies.pop(0), ('203.0.113.9', 5732)

    def gettimeout(self): return None

    def settimeout(self, timeout): pass


class PublicServer:
    # A public server answering a real VPNClient without any network.
    address = '198.51.100.7', 40000

    def setUp(self):
        names = 'accounts', 'networks', 'organizations', 'roles', 'members', 'connections', 'usage'
        self.collections = {name: Collection() for name in names}
        self.database = tunnel.Database(self.collections)
        self.server = VPNServer(tunnel.MongoClient(self.database), 'database', public=True)
        self.server.server.close()
        self.server.server = tunnel.Socket()

    def tearDown(self):
        for item in self.server.waker: item.close()

    def client(self, address=None):
        client = VPNClient(('203.0.113.9', 5732))
        client.socket_server.close()
        client.socket_server = ServerSocket(self.server, address or self.address)
        return client

    def register(self, username='ana', email='ana@example.com', password=PASSWORD, address=None):
        self.client(address).register(username, email, password)

    def accounts(self): return self.collections['accounts'].documents



class RegisterTest(PublicServer, unittest.TestCase):
    def test_a_new_person_registers_and_logs_in_with_only_the_address(self):
        self.register()
        account, = self.accounts()
        self.assertEqual((account['username'], account['email'], account['networks']), ('ana', 'ana@example.com', {}))
        self.assertNotIn('password', account)
        self.assertTrue(srp.check(PASSWORD, account['srp']))
        # Nobody receives an organization they did not ask for.
        self.assertEqual(self.collections['organizations'].documents, [])
        client = self.client()
        cipher = client.authenticate('ana', PASSWORD)
        self.assertEqual(self.server.registry.get_session(cipher.session_id).account_id, account['_id'])
        self.assertEqual(client.account(), dict(username='ana', email='ana@example.com'))
        # Names are found whatever their case, like emails.
        self.assertIsNotNone(self.client().authenticate('ANA', PASSWORD))

    def test_without_networks_the_account_founds_one_or_waits(self):
        self.register()
        client = self.client()
        for action in (client.connect, client.list_networks, lambda: client.create_organization('Taller')):
            with self.assertRaises(VPNError) as raised: action()
            self.assertEqual(raised.exception.code, 'not_authenticated')
        client.authenticate('ana', PASSWORD)
        self.assertEqual(client.list_networks(), [])
        with self.assertRaises(VPNError) as raised: client.connect()
        self.assertEqual(raised.exception.code, 'no_networks')
        # Waiting: an administrator of another organization adds the account.
        organizations = Organizations(self.database)
        owner = self.collections['accounts'].insert_one(dict(username='owner', email='owner@example.com', networks={}))
        other = organizations.create(owner.inserted_id, 'Oficina')
        office = self.collections['networks'].documents[0]['_id']
        account = self.accounts()[0]['_id']
        organizations.join(account, other, office)
        self.assertEqual([network['network_id'] for network in client.list_networks()], [str(office)])
        with mock.patch.object(VPNClient, 'new_tunnel', side_effect=VPNError('tun_missing')), \
                self.assertRaises(VPNError) as raised:
            client.connect()
        self.assertEqual(raised.exception.code, 'tun_missing')
        # Founding: the account administers its own organization, network and panel.
        created = client.create_organization('Taller')
        organization = next(item for item in self.collections['organizations'].documents if item['name'] == 'Taller')
        self.assertEqual(created['organization_id'], str(organization['_id']))
        self.assertTrue(organizations.permissions(account, organization['_id']).administrator)
        self.assertIn(created['network_id'], {str(network_id) for network_id in self.server.bridges})
        self.assertIn(created['network_id'], [network['network_id'] for network in client.list_networks()])

    def test_only_a_public_server_accepts_registrations(self):
        self.server.public = False
        with self.assertRaises(VPNError) as raised: self.register()
        self.assertEqual(raised.exception.code, 'registration_closed')
        self.assertEqual(self.accounts(), [])

    def test_names_and_emails_are_checked_and_unique(self):
        self.register()
        cases = [(dict(username='ANA', email='other@example.com'), 'username_taken'),
                 (dict(username='bea', email='ANA@example.com'), 'email_taken'),
                 (dict(username='a'), 'invalid_username'),
                 (dict(username='ana maria'), 'invalid_username'),
                 (dict(username='x' * 33), 'invalid_username'),
                 (dict(username='bea', email='not-an-email'), 'invalid_email'),
                 (dict(username='bea', email='a@b'), 'invalid_email')]
        for fields, code in cases:
            with self.subTest(fields=fields), self.assertRaises(VPNError) as raised:
                self.register(**dict(dict(username='bea', email='bea@example.com'), **fields))
            self.assertEqual(raised.exception.code, code)
        self.assertEqual(len(self.accounts()), 1)

    def test_a_weak_stretch_is_refused(self):
        client = self.client()
        handshake = client.handshake()
        packet = handshake.register('ana', 'ana@example.com', PASSWORD, iterations=srp.MINIMUM - 1)
        with self.assertRaises(VPNError) as raised: handshake.registered(client.exchange(packet))
        self.assertEqual(raised.exception.code, 'invalid_account')
        self.assertEqual(self.accounts(), [])

    def test_one_address_creates_few_accounts_per_hour(self):
        for number in range(5): self.register(f'user{number}', f'user{number}@example.com')
        with self.assertRaises(VPNError) as raised: self.register('user5', 'user5@example.com')
        self.assertEqual(raised.exception.code, 'too_many_registrations')
        self.register('user5', 'user5@example.com', address=('198.51.100.8', 40000))
        self.assertEqual(len(self.accounts()), 6)

    def test_wrong_passwords_and_unknown_names_fail_alike_and_then_wait(self):
        self.register()
        failures = []
        for username, password in (('ana', 'wrong'), ('ghost', PASSWORD)):
            with self.assertRaises(VPNError) as raised: self.client().authenticate(username, password)
            failures.append((raised.exception.code, str(raised.exception)))
        self.assertEqual(failures, [('incorrect_credentials', 'Incorrect credentials')] * 2)
        for _ in range(3):
            with self.assertRaises(VPNError): self.client().authenticate('ana', 'wrong')
        # The fifth failure from this address starts the wait, even with the right password.
        with self.assertRaises(VPNError) as raised: self.client().authenticate('ana', PASSWORD)
        error = raised.exception
        self.assertEqual((error.code, str(error)), ('too_many_attempts', f"Too many attempts: wait {error.details['wait']} seconds"))
        self.assertGreater(error.details['wait'], 0)
        # Someone else, from elsewhere, is not affected.
        self.register('bea', 'bea@example.com', address=('198.51.100.8', 40000))
        self.assertIsNotNone(self.client(('198.51.100.8', 40000)).authenticate('bea', PASSWORD))

    def test_a_repeated_packet_gets_the_same_answer_and_one_proof_per_exchange(self):
        self.register()
        handshake = ClientHandshake()
        self.server.receive_handshake((handshake.hello(), self.address))
        handshake.server_hello(self.server.server.packets.pop()[0])
        login_packet = handshake.login('ana', PASSWORD)
        self.server.receive_handshake((login_packet, self.address))
        challenge = self.server.server.packets.pop()[0]
        self.server.receive_handshake((login_packet, self.address))
        self.assertEqual(self.server.server.packets.pop()[0], challenge)
        proof = handshake.challenge(challenge)
        self.server.receive_handshake((proof, self.address))
        configuration = self.server.server.packets.pop()[0]
        self.server.receive_handshake((proof, self.address))
        self.assertEqual(self.server.server.packets.pop()[0], configuration)
        self.assertEqual(len(self.server.registry.sessions), 1)
        # A second, different proof in the same exchange gets nothing.
        other = handshake.request(3, b'\x00\x20' + b'\x00' * 32)
        self.server.receive_handshake((other, self.address))
        self.assertEqual(self.server.server.packets, [])
        self.assertIsNotNone(handshake.configuration(configuration))

    def test_one_exchange_answers_a_few_requests_at_most(self):
        handshake = ClientHandshake()
        self.server.receive_handshake((handshake.hello(), self.address))
        handshake.server_hello(self.server.server.packets.pop()[0])
        for number in range(5):
            packet = handshake.register(f'user{number}', f'user{number}@example.com', PASSWORD)
            self.server.receive_handshake((packet, self.address))
        self.assertEqual(len(self.server.server.packets), 4)

    def test_accounts_without_a_usable_record_cannot_log_in(self):
        # An account from before, with a bcrypt hash, or a damaged record.
        accounts = self.collections['accounts'].documents
        accounts.append(dict(username='old', email='old@example.com', password='$2b$12$abc', networks={}))
        accounts.append(dict(username='broken', email='b@example.com', srp=dict(salt='zz'), networks={}))
        for username in ('old', 'broken'):
            with self.subTest(username=username), self.assertRaises(VPNError) as raised:
                self.client().authenticate(username, PASSWORD)
            self.assertEqual(raised.exception.code, 'incorrect_credentials')

    def test_organizations_have_a_valid_name_and_a_limit(self):
        self.register()
        client = self.client()
        client.authenticate('ana', PASSWORD)
        for name in ('', '   ', 'x' * 41, None):
            with self.subTest(name=name), self.assertRaises(VPNError) as raised: client.create_organization(name)
            self.assertEqual(raised.exception.code, 'invalid_name')
        names = [client.create_organization(f' Taller {number} ') and f'Taller {number}' for number in range(ORGANIZATIONS)]
        self.assertEqual([item['name'] for item in self.collections['organizations'].documents], names)
        with self.assertRaises(VPNError) as raised: client.create_organization('Una más')
        error = raised.exception
        self.assertEqual((error.code, error.details, str(error)), (
            'organization_limit', dict(limit=ORGANIZATIONS), f'An account may administer at most {ORGANIZATIONS} organizations'))

    def test_a_lost_session_logs_in_again_without_the_password(self):
        self.register()
        client = self.client()
        client.authenticate('ana', PASSWORD)
        created = client.create_organization('Taller')
        client.select_network(created['network_id'])
        # Only the stretched value stays in memory, never the password.
        self.assertNotIn(PASSWORD, repr(client.remembered))
        self.assertTrue(client.alive())
        self.assertNotIn('error', client.request('ping'))
        # The server restarts: same database, no sessions.
        for socket_ in self.server.waker: socket_.close()
        self.server = VPNServer(tunnel.MongoClient(self.database), 'database', public=True)
        self.server.server.close()
        self.server.server = tunnel.Socket()
        client.socket_server.server = self.server
        self.assertFalse(client.alive())
        with mock.patch.object(VPNClient, 'RETRY', 0):
            self.assertFalse(client.recover())
        self.assertFalse(client.recovering)
        session = self.server.registry.get_session(client.cipher.session_id)
        self.assertEqual((session.username, client.network_id), ('ana', created['network_id']))
        self.assertTrue(client.alive())

    def test_recovery_stops_on_a_changed_password_or_when_asked(self):
        self.register()
        client = self.client()
        client.authenticate('ana', PASSWORD)
        client.network_id = None
        account = self.accounts()[0]
        account['srp'] = srp.verifier('otra clave')
        with self.assertRaises(VPNError) as raised: client.authenticate('ana')
        self.assertEqual(raised.exception.code, 'incorrect_credentials')
        # Recovery gives up on it instead of trying forever.
        with self.assertRaises(VPNError) as raised: client.recover()
        self.assertEqual(raised.exception.code, 'incorrect_credentials')
        # The server stays silent: recovery waits until it is told to stop.
        client.socket_server.sendto = lambda packet, address: None
        client.stop()
        with mock.patch.object(VPNClient, 'RETRY', 0): self.assertTrue(client.recover())
        self.assertFalse(client.recovering)

    def test_the_operator_creates_accounts_on_a_closed_server(self):
        mongo = tunnel.MongoClient(self.database)
        options = argparse.Namespace(username='carla', email='carla@example.com', mongo='', database='database')
        answers = iter([PASSWORD, PASSWORD])
        with mock.patch.object(cli, 'MongoClient', return_value=mongo), mock.patch('builtins.print'):
            cli.add_account(options, ask=lambda prompt: next(answers))
        account, = self.accounts()
        self.assertTrue(srp.check(PASSWORD, account['srp']))
        self.server.public = False
        self.assertIsNotNone(self.client().authenticate('carla', PASSWORD))
        for fields, answers in ((dict(username='CARLA'), [PASSWORD, PASSWORD]), (dict(email='bad'), []),
                                (dict(username='new'), [PASSWORD, 'other'])):
            replies = iter(answers)
            with self.subTest(fields=fields), self.assertRaises(SystemExit), \
                    mock.patch.object(cli, 'MongoClient', return_value=mongo):
                cli.add_account(argparse.Namespace(**dict(vars(options), **fields)), ask=lambda prompt: next(replies))
        self.assertEqual(len(self.accounts()), 1)


class AttemptsTest(unittest.TestCase):
    def test_failures_wait_longer_each_time_after_the_free_ones(self):
        attempts, keys = Attempts(free=2, delay=2, maximum_delay=10), ['ana']
        waits = []
        for moment in range(6):
            attempts.failed(keys, now=100)
            waits.append(attempts.blocked(keys, now=100))
        self.assertEqual(waits, [0, 2, 4, 8, 10, 10])
        attempts.succeeded(keys)
        self.assertEqual(attempts.blocked(keys, now=100), 0)

    def test_the_table_stays_bounded(self):
        attempts = Attempts(limit=3, window=10)
        for number in range(5): attempts.failed([number], now=number)
        self.assertEqual(len(attempts.failures), 3)
        for number in range(3): self.assertTrue(attempts.may_register(f'10.0.0.{number}', now=0))
        self.assertFalse(attempts.may_register('10.0.0.9', now=1))
        self.assertTrue(attempts.may_register('10.0.0.9', now=20))


if __name__ == '__main__': unittest.main()
