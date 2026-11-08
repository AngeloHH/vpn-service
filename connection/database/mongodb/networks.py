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
        arguments.update(max_address=max_address, connections={}, routes={})
        return super().create(**arguments)

    def _get_address(self):
        network, address = self.get(), None
        base_address = network['network_range'].split('/')[0]
        used_addresses = list(network['connections'].values())
        used_addresses += list(network['routes'].values())
        for address_id in range(network['max_address']):
            address = new_address(base_address, address_id)
            if address not in used_addresses: break
        return address

    def _source_network(self, networks: dict,
                        source_network: str or ObjectId = None):
        if not source_network: raise ValueError('A routed identity is required')
        source_id = source_network.__str__()
        target_id = self.id.__str__()
        if source_id == target_id:
            raise ValueError('A routed identity must come from another network')
        if source_id not in networks:
            raise ValueError('The routed source network is not assigned')
        source = networks[source_id]
        if type(source) is not dict or source.get('mode') != 'assigned':
            raise ValueError('A routed network cannot provide an identity')
        return source_id

    def _routed_address(self, network: dict, account_id: str,
                        source_id: str) -> str:
        # The foreign address becomes an explicit return route in this network.
        source = Network(self.collection, source_id).get()
        source_connections = source.get('connections', {}) if source else {}
        ip_address = source_connections.get(account_id)
        if not ip_address: raise ValueError('The routed identity has no address')
        connections, routes = network['connections'], network['routes']
        owners = {address: key for key, address in routes.items()}
        owners.update({address: key for key, address in connections.items()})
        if ip_address in owners and owners[ip_address] != account_id:
            raise AddressConflict(ip_address).already_defined()
        connections.pop(account_id, None)
        routes[account_id] = ip_address
        self.update(connections=connections, routes=routes)
        return ip_address

    def _assigned_address(self, network: dict, account_id: str) -> str:
        # A local lease replaces any foreign route previously owned here.
        arguments = account_id, self._get_address()
        ip_address = network['connections'].get(*arguments)
        address_list = list(network['connections'].items())
        address_list += list(network['routes'].items())
        address_list = {value: key for key, value in address_list}
        if account_id not in network['connections']:
            network['connections'][account_id] = ip_address
            if ip_address in address_list:
                raise AddressConflict(ip_address).already_defined()
        routes = network['routes']
        routes.pop(account_id, None)
        self.update(connections=network['connections'], routes=routes)
        return ip_address

    def to_network(self, account: Account, mode: str = 'assigned',
                   source_network: str or ObjectId = None,
                   primary: bool = False):
        if mode not in ('assigned', 'routed'):
            raise ValueError('Unknown network access mode')
        if mode == 'routed' and primary:
            raise ValueError('A routed network cannot be primary')
        network, account_details = self.get(), account.get()
        networks, account_id = account_details['networks'], account.id.__str__()
        network_id, ip_address = self.id.__str__(), None

        if mode == 'routed':
            source_id = self._source_network(networks, source_network)
            ip_address = self._routed_address(network, account_id, source_id)
            access = dict(mode=mode, source=source_id)
        else:
            ip_address = self._assigned_address(network, account_id)
            access = dict(mode=mode, primary=primary)

        # Exactly one assigned network may provide the reusable identity.
        if primary:
            for membership in networks.values():
                if type(membership) is not dict:
                    raise ValueError('Invalid network membership')
                membership.pop('primary', None)
        networks[network_id] = access
        account.update(networks=networks)
        return ip_address


class Connection(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)
        self.close = lambda **kwargs: self.delete(**kwargs)

    def create(self, account: Account, networks: list, socket: tuple):
        primary = next(network for network in networks if network.primary)
        accesses = [network.configuration() for network in networks]
        return super().create(
            account_id=account.id, network_id=primary.network_id, ip_address=primary.ip_address,
            networks=accesses, connection=':'.join(map(str, socket))
        )
