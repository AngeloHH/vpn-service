import unittest

import bcrypt
from bson import ObjectId
from scapy.layers.inet import IP
from scapy.packet import Raw


from connection.protocol import ClientHandshake
from connection.vpn_service import VPNServer


class InsertResult:
    def __init__(self, inserted_id): self.inserted_id = inserted_id


class Collection:
    def __init__(self, documents=None):
        self.documents, self.operations = documents or [], 0

    def find_one(self, query):
        self.operations += 1
        return next((document for document in self.documents if all(document.get(k) == v for k, v in query.items())), None)

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

    def update_one(self, query, update):
        self.operations += 1
        document = self.find_one(query)
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


class VPNServiceTest(unittest.TestCase):
    def server(self):
        account_id, network_id = ObjectId(), ObjectId()
        password = bcrypt.hashpw(b'password123*', bcrypt.gensalt(4)).decode()
        collections = {
            'accounts': Collection([dict(
                _id=account_id, username='username', password=password,
                networks={network_id.__str__(): {}}
            )]),
            'networks': Collection([dict(
                _id=network_id, subnet_mask='255.255.255.0',
                connections={account_id.__str__(): '192.168.1.2'}
            )]),
            'connections': Collection()
        }
        server = VPNServer(MongoClient(Database(collections)), 'database')
        server.server.close()
        server.server = Socket()
        return server, collections

    def authenticate(self, server, address):
        client = ClientHandshake(server.public_key)
        server.receive_handshake((client.hello(), address))
        client.server_hello(server.server.packets.pop()[0])
        credentials = client.credentials('username', 'password123*')
        server.receive_handshake((credentials, address))
        configuration = server.server.packets.pop()[0]
        return client.configuration(configuration)[2]

    def test_secure_session_routes_without_database_queries(self):
        server, collections = self.server()
        address = '127.0.0.1', 50000
        client = self.authenticate(server, address)
        operations = sum(collection.operations for collection in collections.values())
        packet = bytes(IP(src='192.168.1.2', dst='192.168.1.2') / Raw(b'packet content'))

        server.send_packet(False, (client.encrypt(packet), address))
        encrypted, destination = server.server.packets.pop()

        self.assertEqual(destination, address)
        self.assertEqual(client.decrypt(encrypted), packet)
        self.assertEqual(
            sum(collection.operations for collection in collections.values()),
            operations
        )


if __name__ == '__main__': unittest.main()
