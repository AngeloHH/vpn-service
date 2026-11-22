import re
import socket
import time
import unittest
from unittest import mock

from bson import ObjectId
from scapy.layers.inet import IP
from scapy.packet import Raw
from tcp_sansio import TCPStack


from tests import RECORD, login
from connection.database.mongodb import Account, Network
from connection.protocol import Control, Protocol
from connection.virtual_http import HTTPResponse
from connection.vpn_service import VPNServer


class InsertResult:
    def __init__(self, inserted_id): self.inserted_id = inserted_id


def matches(document: dict, query: dict) -> bool:
    # Equality, plus the $regex form the panel uses for case-insensitive emails.
    def match(value, expected):
        if type(expected) is not dict or '$regex' not in expected: return value == expected
        flags = re.IGNORECASE if 'i' in expected.get('$options', '') else 0
        return type(value) is str and re.search(expected['$regex'], value, flags) is not None
    return all(match(document.get(key), value) for key, value in query.items())


class Collection:
    def __init__(self, documents=None):
        self.documents, self.operations = documents or [], 0

    def find_one(self, query):
        self.operations += 1
        return next((document for document in self.documents if matches(document, query)), None)

    def insert_one(self, document):
        self.operations += 1
        document['_id'] = ObjectId()
        self.documents.append(document.copy())
        return InsertResult(document['_id'])

    def delete_many(self, query):
        self.operations += 1
        self.documents = [
            document for document in self.documents
            if not all(document.get(k) == v for k, v in query.items())
        ]

    def update_one(self, query, update, upsert=False):
        self.operations += 1
        document = self.find_one(query)
        if not document and upsert:
            self.insert_one(dict(query))
            document = self.documents[-1]
        if not document: return
        for key, value in update.get('$set', {}).items(): document[key] = value
        for key, value in update.get('$inc', {}).items(): document[key] = document.get(key, 0) + value


class Database:
    def __init__(self, collections): self.collections = collections
    def __getitem__(self, name): return self.collections[name]


class MongoClient:
    def __init__(self, database): self.database = database
    def __getitem__(self, name): return self.database


class Socket:
    def __init__(self): self.packets = []
    def sendto(self, packet, address): self.packets.append((packet, address))


class LoopTest(unittest.TestCase):
    # The packet loop reads every waiting datagram, then does its upkeep once.
    def setUp(self):
        self.server = VPNServer(MongoClient(Database({'accounts': Collection(), 'networks': Collection(),
                                                      'connections': Collection()})), 'database')
        self.server.server.bind(('127.0.0.1', 0))
        self.address = self.server.server.getsockname()
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tearDown(self):
        self.sender.close()
        self.server.close()

    def send(self, *payloads):
        for payload in payloads: self.sender.sendto(payload, self.address)
        time.sleep(0.05)

    def test_a_wake_handles_every_waiting_datagram_then_its_upkeep_once(self):
        self.send(b'one', b'two', b'three')
        with mock.patch.object(self.server, 'receive') as receive, mock.patch.object(self.server, 'upkeep') as upkeep:
            self.server.serve_once()
        self.assertEqual([call.args[0][0] for call in receive.call_args_list], [b'one', b'two', b'three'])
        upkeep.assert_called_once_with()

    def test_the_batch_stops_at_its_cap(self):
        self.send(*[bytes([n]) for n in range(5)])
        with mock.patch.object(self.server, 'receive') as receive:
            self.assertEqual(self.server.receive_batch(limit=3), 3)
            self.assertEqual(receive.call_count, 3)
            # Called only when select saw data: past the first read it never waits.
            self.assertEqual(self.server.receive_batch(limit=10), 2)

    def test_a_quiet_wake_still_does_its_upkeep(self):
        with mock.patch.object(self.server, 'loop_timeout', return_value=0), \
                mock.patch.object(self.server, 'upkeep') as upkeep, mock.patch.object(self.server, 'receive') as receive:
            self.server.serve_once()
        upkeep.assert_called_once_with()
        receive.assert_not_called()

    def test_datagrams_reach_their_handler_by_type(self):
        with mock.patch.object(self.server, 'send_packet') as data, \
                mock.patch.object(self.server, 'receive_handshake') as handshake, \
                mock.patch.object(self.server, 'receive_control') as control:
            for packet_type in (Protocol.data, Protocol.client_hello, Protocol.control):
                self.server.receive((Protocol.pack(packet_type, bytes(16), bytes(24)), ('127.0.0.1', 1)))
            self.server.receive((b'\xff', ('127.0.0.1', 1)))
        self.assertEqual((data.call_count, handshake.call_count, control.call_count), (1, 1, 1))


class VPNServiceTest(unittest.TestCase):
    def server(self):
        account_id, network_id = ObjectId(), ObjectId()
        collections = {
            'accounts': Collection([dict(
                _id=account_id, username='username', srp=RECORD,
                networks={network_id.__str__(): dict(
                    mode='assigned', primary=True
                )}
            )]),
            'networks': Collection([dict(
                _id=network_id, subnet_mask='255.255.255.0',
                network_range='192.168.1.0/24',
                connections={account_id.__str__(): '192.168.1.2'}, routes={}
            )]),
            'connections': Collection()
        }
        server = VPNServer(MongoClient(Database(collections)), 'database')
        server.server.close()
        server.server = Socket()
        return server, collections

    def login(self, server, address):
        return login(server, address)

    def control(self, server, cipher, address, request=None, **message):
        if request is None: request = cipher.counter + 1
        message = Control.pack(dict(request=request, **message))
        server.receive_control((cipher.encrypt(message, Protocol.control), address))
        reply = server.server.packets.pop()[0]
        return Control.unpack(cipher.decrypt(reply, Protocol.control))

    def authenticate(self, server, address):
        cipher = self.login(server, address)
        options = self.control(server, cipher, address, action='list')['networks']
        network_id = next(option for option in options if option['default'])['network_id']
        self.control(server, cipher, address, action='connect', network_id=network_id)
        return cipher

    def pump(self, server, cipher, address, stack):
        for packet in stack.transmit():
            server.send_packet((cipher.encrypt(packet), address))
        while server.server.packets:
            packet, destination = server.server.packets.pop(0)
            self.assertEqual(destination, address)
            stack.receive(cipher.decrypt(packet))

    def test_secure_session_routes_without_database_queries(self):
        server, collections = self.server()
        address = '127.0.0.1', 50000
        client = self.authenticate(server, address)
        operations = sum(collection.operations for collection in collections.values())
        packet = bytes(IP(src='192.168.1.2', dst='192.168.1.2') / Raw(b'packet content'))

        server.send_packet((client.encrypt(packet), address))
        encrypted, destination = server.server.packets.pop()

        self.assertEqual(destination, address)
        self.assertEqual(client.decrypt(encrypted), packet)
        self.assertEqual(
            sum(collection.operations for collection in collections.values()),
            operations
        )

    def test_routed_access_reuses_the_primary_network_address(self):
        account_id, primary_id, routed_id = ObjectId(), ObjectId(), ObjectId()
        accounts = Collection([dict(
            _id=account_id, username='username', srp=RECORD, networks={}
        )])
        networks = Collection([
            dict(_id=primary_id, subnet_mask='255.255.255.0',
                 network_range='10.10.0.0/24', max_address=10, routes={},
                 connections={account_id.__str__(): '10.10.0.2'}),
            dict(_id=routed_id, subnet_mask='255.255.255.0',
                 network_range='10.20.0.0/24', max_address=10,
                 connections={}, routes={})
        ])
        collections = dict(
            accounts=accounts, networks=networks, connections=Collection()
        )
        account = Account(accounts, account_id)
        Network(networks, primary_id).to_network(account, primary=True)
        Network(networks, routed_id).to_network(
            account, mode='routed', source_network=primary_id
        )
        server = VPNServer(MongoClient(Database(collections)), 'database')
        server.server.close()
        accesses = server.network_accesses(account.get(), primary_id)

        self.assertEqual([access.ip_address for access in accesses],
                         ['10.10.0.2', '10.10.0.2'])
        routed = Network(networks, routed_id).get()
        self.assertEqual(routed['routes'][account_id.__str__()], '10.10.0.2')

    def test_virtual_http_crosses_the_encrypted_udp_tunnel(self):
        server, collections = self.server()
        network_id = collections['networks'].documents[0]['_id']
        http = server.add_virtual_http(network_id, '192.168.1.1')

        @http.route('GET', '/')
        def index(request):
            return HTTPResponse('Virtual router')

        address = '127.0.0.1', 50000
        cipher = self.authenticate(server, address)
        session = server.registry.get_session(cipher.session_id)
        configuration = session.configurations()[0]['server']
        self.assertEqual(configuration,
                         dict(ip_address='192.168.1.1', port=80))
        operations = sum(collection.operations
                         for collection in collections.values())
        stack = TCPStack('192.168.1.2', mtu=1420, seed=1)
        connection = stack.connect('192.168.1.1', 80)

        for _ in range(100):
            self.pump(server, cipher, address, stack)
            if connection.state == 'ESTABLISHED': break
        self.assertEqual(connection.state, 'ESTABLISHED')

        request = b'GET / HTTP/1.1\r\nHost: 192.168.1.1\r\nConnection: close\r\n\r\n'
        self.assertEqual(connection.send(request[:20]), 20)
        for _ in range(5): self.pump(server, cipher, address, stack)
        self.assertEqual(connection.receive(), b'')
        self.assertEqual(connection.send(request[20:]), len(request) - 20)
        response = bytearray()
        for _ in range(100):
            self.pump(server, cipher, address, stack)
            response.extend(connection.receive())
            if connection.eof: break

        self.assertIn(b'HTTP/1.1 200 OK\r\n', response)
        self.assertTrue(response.endswith(b'\r\n\r\nVirtual router'))
        self.assertTrue(connection.eof)
        self.assertEqual(
            sum(collection.operations for collection in collections.values()),
            operations
        )


if __name__ == '__main__': unittest.main()
