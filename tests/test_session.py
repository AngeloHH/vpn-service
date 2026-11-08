import os
import unittest
from types import SimpleNamespace

from bson import ObjectId

from connection.session import NetworkAccess, Session, SessionRegistry


class SessionRegistryTest(unittest.TestCase):
    def session(self, account_id, networks):
        cipher = SimpleNamespace(session_id=os.urandom(16))
        return Session(account_id, networks, ('127.0.0.1', 50000), cipher)

    def new_session(self, account_id, network_id, ip_address):
        access = NetworkAccess(
            network_id, 'assigned', ip_address, '255.255.255.0',
            '192.168.1.0/24', [], True
        )
        return self.session(account_id, [access])

    def test_replaces_every_index_for_the_same_account(self):
        registry = SessionRegistry()
        account_id, network_id = ObjectId(), ObjectId()
        first = self.new_session(account_id, network_id, '192.168.1.2')
        second = self.new_session(account_id, network_id, '192.168.1.3')
        registry.add_session(first)
        registry.add_session(second)

        self.assertIsNone(registry.get_session(first.cipher.session_id))
        self.assertIsNone(registry.get_route(network_id, first.ip_address))
        self.assertIs(registry.get_session(second.cipher.session_id), second)
        self.assertIs(registry.get_route(network_id, second.ip_address), second)

    def test_routes_an_independent_address_for_each_network(self):
        registry = SessionRegistry()
        network_a, network_b = ObjectId(), ObjectId()
        first_networks = [
            NetworkAccess(network_a, 'assigned', '10.10.0.2',
                          '255.255.255.0', '10.10.0.0/24', [], True),
            NetworkAccess(network_b, 'assigned', '10.20.0.2',
                          '255.255.255.0', '10.20.0.0/24', [])
        ]
        second_networks = [NetworkAccess(
            network_b, 'assigned', '10.20.0.3',
            '255.255.255.0', '10.20.0.0/24', [], True
        )]
        first = self.session(ObjectId(), first_networks)
        second = self.session(ObjectId(), second_networks)
        registry.add_session(first), registry.add_session(second)

        client = registry.get_destination(first, '10.20.0.2', '10.20.0.3')
        self.assertIs(client, second)

    def test_routes_a_shared_identity_in_the_target_network(self):
        registry = SessionRegistry()
        network_a, network_b = ObjectId(), ObjectId()
        first_networks = [
            NetworkAccess(network_a, 'assigned', '10.10.0.2',
                          '255.255.255.0', '10.10.0.0/24', [], True),
            NetworkAccess(network_b, 'routed', '10.10.0.2',
                          '255.255.255.0', '10.20.0.0/24', [])
        ]
        second_networks = [NetworkAccess(
            network_b, 'assigned', '10.20.0.3',
            '255.255.255.0', '10.20.0.0/24', [], True
        )]
        first = self.session(ObjectId(), first_networks)
        second = self.session(ObjectId(), second_networks)
        registry.add_session(first), registry.add_session(second)

        outbound = registry.get_destination(first, '10.10.0.2', '10.20.0.3')
        response = registry.get_destination(second, '10.20.0.3', '10.10.0.2')
        self.assertIs(outbound, second)
        self.assertIs(response, first)


if __name__ == '__main__': unittest.main()
