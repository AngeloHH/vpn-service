from ipaddress import ip_network
from itertools import islice

from bson import ObjectId
from pymongo.collection import Collection

from .accounts import Account
from .methods import network_properties
from ..exceptions import AddressConflict


def router_address(network_range: str) -> str:
    # Every network has a panel; by default it takes the last usable host.
    network = ip_network(network_range, strict=False)
    if network.prefixlen >= 31: return network[-1].__str__()
    return (network.broadcast_address - 1).__str__()


class Network(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)

    def create(self, network_range: str or tuple, max_address: int,
               organization_id: ObjectId = None, name: str = None):
        # The name is optional; the panel numbers unnamed networks.
        properties = network_properties(network_range)
        arguments = dict(subnet_mask=properties[1], network_range=properties[2])
        server = dict(ip_address=router_address(properties[2]), port=80)
        # A new network reaches only its own members until someone opens the internet.
        arguments.update(max_address=max_address, connections={}, routes={},
                         server=server, organization_id=organization_id, name=name,
                         internet=False, dns=[], forwards=[])
        return super().create(**arguments)

    def _get_address(self):
        # Hosts exclude the network and broadcast addresses of the range.
        network = self.get()
        used = set(network['connections'].values())
        used.update(network['routes'].values())
        # Forwarding rules listen on addresses of their own.
        used.update(forward['address'] for forward in network.get('forwards') or [])
        server = network.get('server') or {}
        if server.get('ip_address'): used.add(server['ip_address'])
        hosts = ip_network(network['network_range'], strict=False).hosts()
        for address in map(str, islice(hosts, network['max_address'])):
            if address not in used: return address
        raise AddressConflict().exhausted()

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
        connections = network['connections']
        ip_address = connections.get(account_id) or self._get_address()
        address_list = list(connections.items())
        address_list += list(network['routes'].items())
        address_list = {value: key for key, value in address_list}
        if account_id not in connections:
            connections[account_id] = ip_address
            if ip_address in address_list:
                raise AddressConflict(ip_address).already_defined()
        routes = network['routes']
        routes.pop(account_id, None)
        self.update(connections=connections, routes=routes)
        return ip_address

    def to_network(self, account: Account, mode: str = 'assigned',
                   source_network: str or ObjectId = None,
                   primary: bool = False):
        if mode not in ('assigned', 'routed'):
            raise ValueError('Unknown network access mode')
        if mode == 'routed' and primary:
            raise ValueError('A routed network cannot be primary')
        network, account_details = self.get(), account.get()
        networks, account_id = account_details.get('networks', {}), account.id.__str__()
        network_id, ip_address = self.id.__str__(), None

        if mode == 'routed':
            source_id = self._source_network(networks, source_network)
            ip_address = self._routed_address(network, account_id, source_id)
            access = dict(mode=mode, source=source_id)
        else:
            ip_address = self._assigned_address(network, account_id)
            access = dict(mode=mode, primary=primary)

        # Each organization keeps exactly one primary network per account.
        if primary:
            organization_id = network.get('organization_id')
            for other_id, membership in networks.items():
                if type(membership) is not dict:
                    raise ValueError('Invalid network membership')
                other = Network(self.collection, other_id).get() or {}
                if other.get('organization_id') != organization_id: continue
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
