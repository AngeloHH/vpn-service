import os
import socket
import struct
import unittest
from unittest import mock

from bson import ObjectId

from connection import workers as sharding
from connection.database.mongodb import Network
from connection.organizations import Organizations
from connection.protocol import Control, PacketCipher, Protocol
from connection.vpn_service import VPNClient, VPNServer
from tests import RECORD
from tests import test_vpn_service as tunnel
from tests.test_organizations import Collection


def organization_of(worker: int, workers: int = 2) -> ObjectId:
    while True:
        organization_id = ObjectId()
        if sharding.owner(organization_id, workers) == worker: return organization_id


def header(packet_type: int, identifier: bytes) -> bytes:
    return struct.pack('!4sBB16s', Protocol.magic, 2, packet_type, identifier)


class ShardingTest(unittest.TestCase):
    def test_the_session_identifier_names_its_worker(self):
        for workers in (2, 3, 7, 255):
            for worker in range(workers):
                for _ in range(20):
                    self.assertEqual(sharding.worker_of(sharding.session_id(worker, workers), workers), worker)
        self.assertEqual(len(sharding.session_id(0, 1)), 16)

    def test_every_process_agrees_on_the_owner(self):
        organization_id = ObjectId()
        owners = {sharding.owner(organization_id, 4) for _ in range(5)}
        self.assertEqual(len(owners), 1)
        self.assertIn(owners.pop(), range(4))
        self.assertEqual(sharding.owner(organization_id, 1), 0)
        self.assertEqual(sharding.owner(None, 4), 0)
        spread = {sharding.owner(ObjectId(), 4) for _ in range(200)}
        self.assertEqual(spread, {0, 1, 2, 3})

    @unittest.skipUnless(sharding.available(), 'Linux only')
    def test_the_kernel_delivers_each_datagram_to_its_worker(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        group = sharding.group('127.0.0.1', port, 3)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for udp in (*group, sender): self.addCleanup(udp.close)
        for udp in group: udp.settimeout(1)
        cases = [(Protocol.client_hello, os.urandom(16), 0), (Protocol.authentication, os.urandom(16), 0)]
        cases += [(Protocol.control, sharding.session_id(worker, 3), worker) for worker in range(3)]
        cases += [(Protocol.data, sharding.session_id(worker, 3), worker) for worker in range(3)]
        for packet_type, identifier, worker in cases:
            sender.sendto(header(packet_type, identifier) + b'x', ('127.0.0.1', port))
            self.assertEqual(group[worker].recv(100)[5], packet_type)

    def test_mailboxes_carry_messages_between_workers(self):
        mailboxes = sharding.Mailboxes(2)
        self.assertTrue(mailboxes.send(1, dict(kind='drop', session_id=b'1')))
        self.assertEqual(mailboxes.receive(0), [])
        self.assertEqual(mailboxes.receive(1), [dict(kind='drop', session_id=b'1')])


class CipherStateTest(unittest.TestCase):
    def test_a_restored_cipher_continues_the_counters(self):
        keys = os.urandom(32), os.urandom(32)
        server = PacketCipher(b'a' * 16, *keys)
        client = PacketCipher(b'a' * 16, keys[1], keys[0], client=True)
        server.decrypt(client.encrypt(b'one', Protocol.control), Protocol.control)
        replayed = client.encrypt(b'two', Protocol.control)
        server.decrypt(replayed, Protocol.control)
        moved = PacketCipher.restored(b'b' * 16, server.state())
        # The old identifier still opens a packet, and replays stay refused.
        with self.assertRaises(ValueError): moved.decrypt(replayed, Protocol.control, b'a' * 16)
        self.assertEqual(moved.decrypt(client.encrypt(b'three', Protocol.control), Protocol.control, b'a' * 16),
                         b'three')
        reply = moved.encrypt(b'four', Protocol.control, b'a' * 16)
        self.assertEqual(client.decrypt(reply, Protocol.control), b'four')
        client.session_id = b'b' * 16
        self.assertEqual(moved.decrypt(client.encrypt(b'five', Protocol.control), Protocol.control), b'five')


class Router:
    # The kernel's part: each datagram reaches the worker its header names; mailboxes run between.
    def __init__(self, servers, address, lost: int = 0):
        self.servers, self.address, self.lost, self.inbox = servers, address, lost, []

    def deliver(self):
        moving = True
        while moving:
            moving = False
            for server in self.servers:
                if self.waiting(server):
                    server.receive_messages()
                    moving = True
        replies = []
        for server in self.servers: replies, server.server.packets = replies + server.server.packets, []
        return replies

    @staticmethod
    def waiting(server) -> bool:
        try: return bool(server.mailboxes.inbox(server.worker).recv(1 << 20, socket.MSG_PEEK | socket.MSG_DONTWAIT))
        except BlockingIOError: return False

    def sendto(self, packet, address):
        worker = sharding.worker_of(Protocol.unpack(packet, Protocol.control)[1], len(self.servers))
        self.servers[worker].receive_control((packet, self.address))
        replies = self.deliver()
        if self.lost: self.lost -= 1
        else: self.inbox += [packet for packet, _ in replies]

    def recvfrom(self, size):
        if not self.inbox: raise socket.timeout()
        return self.inbox.pop(0), ('127.0.0.1', 5732)

    def gettimeout(self): return None
    def settimeout(self, timeout): pass


class MigrationTest(unittest.TestCase):
    address = '127.0.0.1', 50000

    def setUp(self):
        names = 'accounts', 'networks', 'organizations', 'roles', 'members', 'connections', 'usage'
        self.collections = {name: Collection() for name in names}
        database = tunnel.Database(self.collections)
        organizations = Organizations(database)
        self.account_id = ObjectId()
        self.collections['accounts'].documents.append(dict(
            _id=self.account_id, username='username', email='username@example.com', srp=RECORD, networks={}))
        # The organization belongs to the second worker.
        self.organization = organizations.create(self.account_id)
        while sharding.owner(self.organization, 2) != 1: self.organization = organizations.create(self.account_id)
        self.network_id = Network(self.collections['networks']).get(organization_id=self.organization)['_id']
        mongo, mailboxes = tunnel.MongoClient(database), sharding.Mailboxes(2)
        self.servers = []
        for worker in range(2):
            server = VPNServer(mongo, 'database', 'ab' * 32, worker=worker, workers=2, mailboxes=mailboxes)
            server.server.close()
            server.server = tunnel.Socket()
            for end in server.waker: self.addCleanup(end.close)
            self.servers.append(server)

    def client(self, lost: int = 0) -> VPNClient:
        client = VPNClient(('127.0.0.1', 5732))
        client.cipher = tunnel.login(self.servers[0], self.address)
        client.socket_server.close()
        client.socket_server = Router(self.servers, self.address, lost)
        self.addCleanup(lambda: [command.close() for command in client.commands])
        return client

    def test_logins_open_in_the_front_worker(self):
        client = self.client()
        self.assertEqual(sharding.worker_of(client.cipher.session_id, 2), 0)
        self.assertTrue(self.servers[0].registry.get_account(self.account_id))

    def test_connecting_moves_the_session_to_its_organization(self):
        client = self.client()
        old = client.cipher.session_id
        networks = client.select_network(str(self.network_id))
        self.assertEqual(networks[0]['network_id'], str(self.network_id))
        self.assertNotEqual(client.cipher.session_id, old)
        self.assertEqual(sharding.worker_of(client.cipher.session_id, 2), 1)
        self.assertIsNone(self.servers[0].registry.get_account(self.account_id))
        session = self.servers[1].registry.get_account(self.account_id)
        self.assertEqual(session.cipher.session_id, client.cipher.session_id)
        self.assertIn(self.organization, self.servers[1].organizations_loaded)
        self.assertNotIn(self.organization, self.servers[0].organizations_loaded)
        # Later requests reach the new worker directly.
        request = session.request
        client.ask(Control.ping)
        self.assertEqual(session.request, request + 1)

    def test_a_lost_reply_is_answered_from_the_new_worker_once(self):
        client = self.client(lost=1)
        networks = client.select_network(str(self.network_id))
        self.assertEqual(networks[0]['network_id'], str(self.network_id))
        self.assertEqual(sharding.worker_of(client.cipher.session_id, 2), 1)
        self.assertEqual(len(self.collections['connections'].documents), 1)

    def test_a_new_login_drops_the_session_in_another_worker(self):
        client = self.client()
        client.select_network(str(self.network_id))
        self.assertTrue(self.servers[1].registry.get_account(self.account_id))
        tunnel.login(self.servers[0], self.address)
        self.servers[1].receive_messages()
        self.assertIsNone(self.servers[1].registry.get_account(self.account_id))
        self.assertTrue(self.servers[0].registry.get_account(self.account_id))

    def test_a_session_that_cannot_move_stays_unconnected_until_the_retry(self):
        client = self.client()
        old = client.cipher.session_id
        with mock.patch.object(self.servers[0].mailboxes, 'send', return_value=False):
            request = self.servers[0].registry.get_account(self.account_id).request
            message = Control.pack(dict(request=request + 1, action=Control.connect, network_id=str(self.network_id)))
            self.servers[0].receive_control((client.cipher.encrypt(message, Protocol.control), self.address))
        session = self.servers[0].registry.get_account(self.account_id)
        # Not connected in the wrong worker, so no organization runs without its rules.
        self.assertEqual(session.request, request)
        self.assertNotIn(self.organization, self.servers[0].organizations_loaded)
        self.assertEqual(self.servers[0].server.packets, [])
        networks = client.select_network(str(self.network_id))
        self.assertEqual(networks[0]['network_id'], str(self.network_id))
        self.assertNotEqual(client.cipher.session_id, old)

    def test_only_the_owner_activates_an_organization(self):
        self.client()
        session = self.servers[0].registry.get_account(self.account_id)
        account = self.collections['accounts'].find_one(dict(_id=self.account_id))
        reply = self.servers[0].activate(session, account, str(self.network_id))
        self.assertEqual(reply.get('error'), 'network_unavailable')
        self.assertNotIn(self.organization, self.servers[0].organizations_loaded)

    def test_moved_identifiers_expire(self):
        client = self.client()
        old = client.cipher.session_id
        client.select_network(str(self.network_id))
        self.assertIn(old, self.servers[0].moved)
        self.assertIn(old, self.servers[1].aliases)
        for server in self.servers:
            for table in (server.moved, server.aliases):
                for key, value in table.items(): table[key] = value[0], 0
            server.last_cleanup = float('-inf')
            server.cleanup_handshakes()
        self.assertFalse(self.servers[0].moved or self.servers[1].aliases)


if __name__ == '__main__': unittest.main()
