import re
from functools import wraps
from ipaddress import ip_address as parse_address, ip_network

from bson import ObjectId

from connection.database.mongodb import Account, Member, Network
from connection.egress import public
from connection.forwarding import PROTOCOLS
from connection.network_admin import NAME_LENGTH, NetworkError

FORWARDS = 100


def serialized(method):
    # The same lock as the network writes: an address is never taken twice.
    @wraps(method)
    def run(self, *arguments, **fields):
        with self.lock: return method(self, *arguments, **fields)
    return run


def forward_addresses(network: dict) -> set:
    return {forward['address'] for forward in network.get('forwards') or []}


class AccessAdmin:
    """Ways into a network from elsewhere, as the "Acceso entre redes" page edits them.

    Routes let a member enter with the address of another of its networks.
    Forwards give an address of the network that leads to another address,
    in the organization or on the internet, on one port or on all of them.
    """

    def __init__(self, network_admin):
        self.admin, self.lock = network_admin, network_admin.lock

    @property
    def networks(self): return self.admin.networks

    @property
    def accounts(self): return self.admin.accounts

    # ---------- Routes ----------

    def routes(self, organization_id, network_id) -> list:
        # Worker thread: who enters this network with an address from another one.
        network = self.admin._network(organization_id, network_id)
        rows = []
        for account_id, ip_address in network['routes'].items():
            account = Account(self.accounts, account_id).get() or {}
            membership = account.get('networks', {}).get(network['_id'].__str__(), {})
            source = Network(self.networks, membership.get('source')).get() if membership.get('source') else None
            rows.append(dict(account_id=account_id, username=account.get('username'), email=account.get('email'),
                             ip=ip_address, source_id=source and source['_id'].__str__(),
                             source_name=source and source.get('name'),
                             source_range=source and source['network_range']))
        return sorted(rows, key=lambda row: int(parse_address(row['ip'])))

    @serialized
    def add_route(self, actor_id, organization_id, network_id, email, source_id) -> dict:
        actor = self.admin._allow(actor_id, organization_id, 'addresses:add', network_id)
        network = self.admin._network(organization_id, network_id)
        if type(email) is not str or not email.strip(): raise NetworkError('unknown_account')
        pattern = '^' + re.escape(email.strip()) + '$'
        account = self.accounts.find_one(dict(email={'$regex': pattern, '$options': 'i'}))
        member = account and Member(self.admin.organizations.members).get(
            organization_id=organization_id, account_id=account['_id'])
        if not member: raise NetworkError('unknown_account')
        self.admin.organizations._target(actor, organization_id, account['_id'])
        if network['_id'].__str__() in account.get('networks', {}): raise NetworkError('already_assigned')
        # The address it brings is the one it has in that other network of the organization.
        try: source = self.admin._network(organization_id, source_id)
        except NetworkError: raise NetworkError('invalid_source')
        membership = account.get('networks', {}).get(source['_id'].__str__(), {})
        # Its own address in this network would already be an assignment here.
        if membership.get('mode') != 'assigned':
            raise NetworkError('invalid_source')
        ip_address = Network(self.networks, network['_id']).to_network(
            Account(self.accounts, account['_id']), 'routed', source['_id'])
        event = dict(kind='route_added', network_id=network['_id'], username=account.get('username'), ip=ip_address)
        # The member reconnects through its source network to receive this one, and the
        # members connected through this network to receive the route to its address.
        reconnect = [(account['_id'], source['_id'])] + self.connected_through(network)
        return dict(result=dict(ip=ip_address), reconnect=reconnect, event=event)

    @staticmethod
    def connected_through(network: dict) -> list:
        # Pairs for VPNServer.reconnect: only sessions whose primary is this network are renewed.
        return [(ObjectId(account_id), network['_id']) for account_id in network.get('connections', {})]

    @serialized
    def remove_route(self, actor_id, organization_id, network_id, account_id) -> dict:
        actor = self.admin._allow(actor_id, organization_id, 'addresses:delete', network_id)
        network = self.admin._network(organization_id, network_id)
        account_id = account_id.__str__() if account_id is not None else ''
        if account_id not in network['routes']: raise NetworkError('account_not_found')
        self.admin.organizations._target(actor, organization_id, ObjectId(account_id))
        account = Account(self.accounts, account_id).get() or {}
        source = account.get('networks', {}).get(network['_id'].__str__(), {}).get('source')
        plan = self.admin._detach(organization_id, network['_id'], account_id)
        self.admin._apply_detach(organization_id, plan)
        event = dict(kind='route_removed', network_id=network['_id'], username=account.get('username'))
        reconnect = [(ObjectId(account_id), ObjectId(source))] if source else []
        # The others in this network drop the route to that address.
        return dict(result=None, reconnect=reconnect + self.connected_through(network), event=event)

    # ---------- Forwards ----------

    def _resolve(self, organization_id, target: str):
        # The organization network that holds the target; None means the internet.
        address = parse_address(target)
        for network in self.admin._organization_networks(organization_id):
            if address in ip_network(network['network_range'], strict=False): return network
        return None

    def _state(self, organization_id, network: dict, forward: dict) -> str:
        if not forward['enabled']: return 'off'
        holder = self._resolve(organization_id, forward['target'])
        if holder: return 'ok'
        if not public(forward['target']): return 'no_target'
        return 'ok' if self.admin.internet() and network.get('internet') is True else 'no_internet'

    def forwards(self, organization_id, network_id) -> list:
        # Worker thread: the rules of a network, with whether they work right now.
        network = self.admin._network(organization_id, network_id)
        rows = [dict(forward, state=self._state(organization_id, network, forward))
                for forward in network.get('forwards') or []]
        return sorted(rows, key=lambda row: (int(parse_address(row['address'])), row['port'] or 0))

    @staticmethod
    def _port(value):
        if value is None: return None
        if type(value) is not int or not 1 <= value <= 65535: raise NetworkError('invalid_port')
        return value

    def _validate(self, organization_id, network: dict, body: dict, own_id=None) -> dict:
        name = self.admin._name(body.get('name'))
        protocol = body.get('protocol')
        if protocol not in PROTOCOLS: raise NetworkError('invalid_request')
        port, target_port = self._port(body.get('port')), self._port(body.get('target_port'))
        # Every port leads to the same port: a single target port has no meaning then.
        if port is None and target_port is not None: raise NetworkError('invalid_port')
        if type(body.get('enabled', True)) is not bool: raise NetworkError('invalid_request')

        # The address it listens on is a free host of this network.
        address = self.admin._host(body.get('address'), network['network_range'])
        router = (network.get('server') or {}).get('ip_address')
        taken = set(network['connections'].values()) | set(network['routes'].values()) | {router}
        if address in taken: raise NetworkError('address_in_use')
        protocols = set(PROTOCOLS[protocol])
        for other in network.get('forwards') or []:
            if other['id'] == own_id or other['address'] != address: continue
            ports_meet = port is None or other['port'] is None or port == other['port']
            if ports_meet and protocols & set(PROTOCOLS[other['protocol']]): raise NetworkError('forward_conflict')

        # The target is a host of an organization network, or a public internet address.
        try: target = parse_address(body.get('target'))
        except (TypeError, ValueError): raise NetworkError('invalid_target')
        if target.version != 4: raise NetworkError('invalid_target')
        holder = self._resolve(organization_id, target.__str__())
        if holder:
            try: target = self.admin._host(target.__str__(), holder['network_range'])
            except NetworkError: raise NetworkError('invalid_target')
            holder_router = (holder.get('server') or {}).get('ip_address')
            # A rule never leads to a panel or to another rule.
            if target == holder_router or target in forward_addresses(holder) or target == address:
                raise NetworkError('invalid_target')
        elif not public(target.__str__()): raise NetworkError('invalid_target')
        else:
            target = target.__str__()
            if not self.admin.internet() or network.get('internet') is not True:
                raise NetworkError('internet_disabled')
        return dict(name=name, address=address, port=port, protocol=protocol, target=target,
                    target_port=target_port, enabled=body.get('enabled', True))

    def _save(self, network: dict, forwards: list, event: dict) -> dict:
        Network(self.networks, network['_id']).update(forwards=forwards)
        organization_id = network['organization_id']
        return dict(result=None, forwards=(organization_id, self.table(organization_id)), event=event)

    @serialized
    def add_forward(self, actor_id, organization_id, network_id, body: dict) -> dict:
        self.admin._allow(actor_id, organization_id, 'forwards:add', network_id)
        network = self.admin._network(organization_id, network_id)
        forwards = list(network.get('forwards') or [])
        if len(forwards) >= FORWARDS: raise NetworkError('forward_limit', maximum=FORWARDS)
        forward = dict(id=ObjectId().__str__(), **self._validate(organization_id, network, body))
        forwards.append(forward)
        effects = self._save(network, forwards, self._event('forward_added', network, forward))
        effects['result'] = dict(id=forward['id'])
        return effects

    @serialized
    def update_forward(self, actor_id, organization_id, network_id, forward_id, body: dict) -> dict:
        self.admin._allow(actor_id, organization_id, 'forwards:modify', network_id)
        network = self.admin._network(organization_id, network_id)
        forwards = list(network.get('forwards') or [])
        index = self._index(forwards, forward_id)
        forward = dict(id=forwards[index]['id'], **self._validate(organization_id, network, body, forwards[index]['id']))
        forwards[index] = forward
        return self._save(network, forwards, self._event('forward_changed', network, forward))

    @serialized
    def delete_forward(self, actor_id, organization_id, network_id, forward_id) -> dict:
        self.admin._allow(actor_id, organization_id, 'forwards:delete', network_id)
        network = self.admin._network(organization_id, network_id)
        forwards = list(network.get('forwards') or [])
        forward = forwards.pop(self._index(forwards, forward_id))
        return self._save(network, forwards, self._event('forward_removed', network, forward))

    @staticmethod
    def _index(forwards: list, forward_id) -> int:
        for index, forward in enumerate(forwards):
            if forward['id'] == forward_id: return index
        raise NetworkError('forward_not_found')

    @staticmethod
    def _event(kind: str, network: dict, forward: dict) -> dict:
        return dict(kind=kind, network_id=network['_id'], address=forward['address'], port=forward['port'],
                    target=forward['target'], target_port=forward['target_port'])

    def with_table(self, organization_id, write) -> dict:
        # A network write can move a rule's target: the table is rebuilt in the same lock.
        with self.lock:
            effects = write()
            effects['forwards'] = organization_id, self.table(organization_id)
            return effects

    def table(self, organization_id) -> dict:
        # What the packet path uses: enabled rules whose target exists, per network.
        networks = self.admin._organization_networks(organization_id)
        table = {}
        for network in networks:
            rules = []
            for forward in network.get('forwards') or []:
                if not forward['enabled']: continue
                holder = self._resolve(organization_id, forward['target'])
                if not holder and not public(forward['target']): continue
                rules.append(dict(forward, organization_id=organization_id,
                                  target_network=holder and holder['_id']))
            if rules: table[network['_id']] = rules
        return table
