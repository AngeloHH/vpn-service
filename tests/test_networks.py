import unittest

from bson import ObjectId

from connection.database.exceptions import AddressConflict
from connection.database.mongodb import Account, Network
from tests import test_vpn_service as tunnel


class AddressTest(unittest.TestCase):
    def network(self, network_range: str, max_address: int, **fields):
        self.network_id = ObjectId()
        document = dict(_id=self.network_id, network_range=network_range,
                        max_address=max_address, connections={}, routes={})
        document.update(fields)
        self.networks = tunnel.Collection([document])
        self.accounts = tunnel.Collection()
        return Network(self.networks, self.network_id)

    def join(self, network: Network) -> str:
        account_id = ObjectId()
        self.accounts.documents.append(dict(_id=account_id, networks={}))
        return network.to_network(Account(self.accounts, account_id))

    def test_the_network_address_is_never_assigned(self):
        network = self.network('10.10.0.0/24', 10)
        self.assertEqual(self.join(network), '10.10.0.1')
        self.assertEqual(self.join(network), '10.10.0.2')

    def test_reserved_addresses_are_skipped(self):
        server = dict(ip_address='10.10.0.1', port=80)
        network = self.network('10.10.0.0/24', 10, server=server,
                               routes={str(ObjectId()): '10.10.0.2'})
        self.assertEqual(self.join(network), '10.10.0.3')

    def test_addresses_continue_across_octets(self):
        used = {str(ObjectId()): f'10.0.0.{host}' for host in range(1, 256)}
        network = self.network('10.0.0.0/16', 300, connections=used)
        self.assertEqual(self.join(network), '10.0.1.0')

    def test_a_full_network_is_rejected(self):
        network = self.network('10.10.0.0/30', 10)
        self.assertEqual([self.join(network), self.join(network)],
                         ['10.10.0.1', '10.10.0.2'])
        with self.assertRaises(AddressConflict): self.join(network)

    def test_the_address_limit_is_respected(self):
        network = self.network('10.10.0.0/24', 2)
        self.join(network), self.join(network)
        with self.assertRaises(AddressConflict): self.join(network)

    def test_a_member_keeps_its_address_in_a_full_network(self):
        network = self.network('10.10.0.0/30', 10)
        account_id = ObjectId()
        self.accounts.documents.append(dict(_id=account_id, networks={}))
        account = Account(self.accounts, account_id)
        first = network.to_network(account)
        self.join(network)
        self.assertEqual(network.to_network(account), first)


if __name__ == '__main__': unittest.main()
