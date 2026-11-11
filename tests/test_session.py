import os
import unittest
from types import SimpleNamespace

from bson import ObjectId

from connection.session import NetworkAccess, Session, SessionRegistry


class SessionRegistryTest(unittest.TestCase):
    def session(self, account_id, networks, registry=None):
        cipher = SimpleNamespace(session_id=os.urandom(16))
        session = Session(account_id, ('127.0.0.1', 50000), cipher)
        if registry: registry.add_session(session), registry.set_networks(session, networks)
        return session

    def access(self, network_id, ip_address):
        return NetworkAccess(network_id, 'assigned', ip_address,
                             '255.255.255.0', '192.168.1.0/24', [], True)

    def test_the_configuration_carries_internet_and_dns(self):
        access = NetworkAccess(ObjectId(), 'assigned', '192.168.1.2', '255.255.255.0',
                               '192.168.1.0/24', [], True, internet=True, dns=['192.168.1.53'])
        configuration = access.configuration()
        self.assertEqual((configuration['internet'], configuration['dns']), (True, ['192.168.1.53']))
        self.assertEqual(self.access(ObjectId(), '192.168.1.3').configuration()['dns'], [])

    def test_replaces_every_index_for_the_same_account(self):
        registry = SessionRegistry()
        account_id, network_id = ObjectId(), ObjectId()
        first = self.session(account_id, [self.access(network_id, '192.168.1.2')], registry)
        second = self.session(account_id, [self.access(network_id, '192.168.1.3')], registry)

        self.assertIsNone(registry.get_session(first.cipher.session_id))
        self.assertIsNone(registry.get_route(network_id, '192.168.1.2'))
        self.assertIs(registry.get_session(second.cipher.session_id), second)
        self.assertIs(registry.get_route(network_id, '192.168.1.3'), second)

    def test_a_login_has_no_routes_until_a_network_is_set(self):
        registry, network_id = SessionRegistry(), ObjectId()
        session = self.session(ObjectId(), [])
        registry.add_session(session)
        self.assertFalse(session.owns_address('192.168.1.2'))
        registry.set_networks(session, [self.access(network_id, '192.168.1.2')])
        self.assertIs(registry.get_route(network_id, '192.168.1.2'), session)

    def test_switching_networks_releases_the_previous_routes(self):
        registry, network_a, network_b = SessionRegistry(), ObjectId(), ObjectId()
        session = self.session(ObjectId(), [self.access(network_a, '192.168.1.2')], registry)
        registry.set_networks(session, [self.access(network_b, '192.168.1.9')])

        self.assertIsNone(registry.get_route(network_a, '192.168.1.2'))
        self.assertIs(registry.get_route(network_b, '192.168.1.9'), session)
        self.assertFalse(session.owns_address('192.168.1.2'))

    def test_a_collision_keeps_the_current_routes(self):
        registry, network_id = SessionRegistry(), ObjectId()
        owner = self.session(ObjectId(), [self.access(network_id, '192.168.1.2')], registry)
        other = self.session(ObjectId(), [self.access(network_id, '192.168.1.3')], registry)

        with self.assertRaises(ValueError):
            registry.set_networks(other, [self.access(network_id, '192.168.1.2')])
        self.assertIs(registry.get_route(network_id, '192.168.1.2'), owner)
        self.assertIs(registry.get_route(network_id, '192.168.1.3'), other)

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
        first = self.session(ObjectId(), first_networks, registry)
        second = self.session(ObjectId(), second_networks, registry)

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
        first = self.session(ObjectId(), first_networks, registry)
        second = self.session(ObjectId(), second_networks, registry)

        outbound = registry.get_destination(first, '10.10.0.2', '10.20.0.3')
        response = registry.get_destination(second, '10.20.0.3', '10.10.0.2')
        self.assertIs(outbound, second)
        self.assertIs(response, first)


if __name__ == '__main__': unittest.main()
