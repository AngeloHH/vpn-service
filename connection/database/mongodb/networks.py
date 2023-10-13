import os

from bson import ObjectId
from pymongo.collection import Collection

from .accounts import Account
from .methods import network_properties, new_address
from ..exceptions import AddressConflict


class Network(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)

    def create(self, network_range: str or tuple, max_address: int):
        properties = network_properties(network_range)
        arguments = dict(subnet_mask=properties[1], network_range=properties[2])
        return super().create(max_address=max_address, connections={}, **arguments)

    def _get_address(self):
        network, address = self.get(), None
        base_address = network['network_range'].split('/')[0]
        # Iterate through available IP addresses in the network.
        for address_id in range(network['max_address']):
            # If the IP address is not in use, assign it to
            # the account.
            address = new_address(base_address, address_id)
            if address not in network['connections'].values():
                break
        return address

    def to_network(self, account: Account):
        network, account_details = self.get(), account.get()
        # If not, add the network ID to the account's networks
        # with an initial empty IP address.
        if network['_id'] not in account_details['networks']:
            networks = account_details['networks']
            networks[self.id.__str__()] = dict(ip_address=None)
            account.update(networks=networks)
        # Try to get the IP address from network's connections.
        arguments = account.id, self._get_address()
        ip_address = network['connections'].get(*arguments)
        address_list = network['connections'].items()
        address_list = {value: key for key, value in address_list}
        if account.id.__str__() not in network['connections']:
            network['connections'][account.id.__str__()] = ip_address
            if ip_address in address_list:
                raise AddressConflict(ip_address).already_defined()
            # Update the network with the new connections.
            self.update(connections=network['connections'])
        return ip_address


class Connection(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)
        self.close, self.length = lambda **kwargs: self.delete(**kwargs), 40

    def create(self, network: Network, account: Account, ip_address: str, socket: tuple):
        return super().create(
            account_id=account.id,
            encrypt=os.urandom(int(self.length / 2)).hex(),
            network_id=network.id,
            ip_address=ip_address,
            connection=':'.join(map(str, socket))
        )
