import os
import unittest
from types import SimpleNamespace

from bson import ObjectId

from connection.session import Session, SessionRegistry


class SessionRegistryTest(unittest.TestCase):
    def new_session(self, account_id, network_id, ip_address):
        cipher = SimpleNamespace(session_id=os.urandom(16))
        arguments = account_id, network_id, ip_address, ('127.0.0.1', 50000)
        arguments += cipher, '255.255.255.0'
        return Session(*arguments)

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


if __name__ == '__main__': unittest.main()
