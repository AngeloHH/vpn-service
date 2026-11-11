import re
from functools import wraps
from ipaddress import ip_address as parse_address, ip_network
from itertools import islice
from threading import RLock

from bson import ObjectId

from connection import limits as speed
from connection.database.mongodb import Account, Member, Network, Organization, Role
from connection.database.mongodb.methods import network_properties
from connection.database.mongodb.networks import router_address
from connection.permissions import Permissions

NAME_LENGTH = 40
DNS_SERVERS = 2
PAGE, MAX_PAGE = 25, 500


def serialized(method):
    # Panel workers run in parallel; one write at a time keeps each check valid.
    @wraps(method)
    def run(self, *arguments, **fields):
        with self.lock: return method(self, *arguments, **fields)
    return run


class NetworkError(ValueError):
    # The code lets the panel explain the refusal in its own language.
    def __init__(self, code: str, **fields):
        super().__init__(code)
        self.code, self.fields = code, fields


class Confirmation(Exception):
    # Raised before any write: these accounts would leave the organization.
    def __init__(self, accounts: list):
        super().__init__('Confirmation required')
        self.accounts = accounts


class NetworkAdmin:
    # Every method writes MongoDB only and returns the live effects to apply.
    def __init__(self, organizations, internet=lambda: True):
        # internet() tells whether the server itself lets traffic out.
        self.organizations, self.database = organizations, organizations.database
        self.internet = internet
        # Reentrant: AccessAdmin shares it and may read the forwarding table inside a write.
        self.lock = RLock()

    @property
    def networks(self): return self.database['networks']

    @property
    def accounts(self): return self.database['accounts']

    def _allow(self, actor_id, organization_id, permission: str, network_id=None):
        actor = self.organizations.permissions(actor_id, organization_id)
        if not actor.allows(permission, network_id):
            raise PermissionError(f'{permission} is not allowed')
        return actor

    def _network(self, organization_id, network_id) -> dict:
        network = Network(self.networks, network_id).get() if ObjectId.is_valid(network_id.__str__()) else None
        if not network or network.get('organization_id') != organization_id:
            raise NetworkError('network_not_found')
        return network

    def _organization_networks(self, organization_id) -> list:
        networks = self.networks.find(dict(organization_id=organization_id))
        return sorted(networks, key=lambda network: network['_id'].__str__())

    @staticmethod
    def _range(network_range) -> str:
        # IPv4 with room for the panel and at least one member: up to /30.
        try: network = ip_network(network_range, strict=False)
        except (TypeError, ValueError): raise NetworkError('invalid_range')
        if network.version != 4 or network.prefixlen > 30: raise NetworkError('invalid_range')
        return network.__str__()

    def _overlap(self, organization_id, network_range: str, own_id=None):
        candidate = ip_network(network_range)
        for network in self._organization_networks(organization_id):
            if network['_id'] == own_id: continue
            if candidate.overlaps(ip_network(network['network_range'], strict=False)):
                raise NetworkError('range_overlap', name=network.get('name'),
                                   network_range=network['network_range'])

    @staticmethod
    def _name(name):
        if name is None: return None
        if type(name) is not str or len(name.strip()) > NAME_LENGTH: raise NetworkError('invalid_name')
        return name.strip() or None

    @staticmethod
    def _dns(servers) -> list:
        # Up to two IPv4 addresses that can answer queries: not multicast, not 0.0.0.0.
        if type(servers) is not list or len(servers) > DNS_SERVERS: raise NetworkError('invalid_dns')
        result = []
        for server in servers:
            try: address = parse_address(server) if type(server) is str else None
            except ValueError: address = None
            if not address or address.version != 4 or address.is_multicast or address.is_unspecified:
                raise NetworkError('invalid_dns')
            if address.__str__() not in result: result.append(address.__str__())
        return result

    @staticmethod
    def _limit(max_address, network_range: str, used: int) -> int:
        # The panel keeps one host, so members may use the rest at most.
        hosts = ip_network(network_range).num_addresses - 2
        if type(max_address) is not int or not 1 <= max_address <= hosts - 1:
            raise NetworkError('invalid_limit', maximum=hosts - 1)
        if max_address < used: raise NetworkError('limit_in_use', used=used)
        return max_address

    @staticmethod
    def _host(address, network_range: str, max_address: int = None) -> str:
        # A usable host of the range; members also stay inside the limit.
        network = ip_network(network_range)
        try: address = parse_address(address)
        except (TypeError, ValueError): raise NetworkError('invalid_address')
        offset = int(address) - int(network.network_address)
        last = network.num_addresses - 2 if max_address is None else max_address
        if address not in network or not 1 <= offset <= last: raise NetworkError('invalid_address')
        return address.__str__()

    # ---------- Networks ----------

    @serialized
    def create(self, actor_id, organization_id, network_range, max_address=None, name=None) -> dict:
        # A new network has no members yet; its panel starts with it.
        self._allow(actor_id, organization_id, 'networks:add')
        network_range, name = self._range(network_range), self._name(name)
        self._overlap(organization_id, network_range)
        hosts = ip_network(network_range).num_addresses - 2
        max_address = self._limit(hosts - 1 if max_address is None else max_address, network_range, 0)
        network = Network(self.networks)
        network.create(network_range, max_address, organization_id, name)
        event = dict(kind='network_created', network_id=network.id, name=name, network_range=network_range)
        return dict(result=dict(network_id=network.id.__str__()), panel=('add', network.id), event=event)

    @serialized
    def update(self, actor_id, organization_id, network_id, name=None, network_range=None,
               max_address=None, router=None, internet=None, dns=None,
               expected: dict = None) -> dict:
        self._allow(actor_id, organization_id, 'networks:modify', network_id)
        network = self._network(organization_id, network_id)
        # Someone else saved after this form was loaded: refuse instead of overwriting.
        before = self._editable(network)
        if expected is not None and expected != before: raise NetworkError('changed')
        connections, routes = dict(network['connections']), network['routes']
        current_range = ip_network(network['network_range'], strict=False).__str__()
        current_router = (network.get('server') or {}).get('ip_address')
        changes = {} if name is None else dict(name=self._name(name))
        if internet is not None:
            if type(internet) is not bool: raise NetworkError('invalid_request')
            if internet and not self.internet(): raise NetworkError('internet_disabled')
            changes['internet'] = internet
        opened = internet is not None and internet != (network.get('internet') is True)
        if dns is not None:
            changes['dns'] = self._dns(dns)
            opened = opened or changes['dns'] != before['dns']

        new_range = current_range if network_range is None else self._range(network_range)
        moved = new_range != current_range
        if moved: self._overlap(organization_id, new_range, network['_id'])
        limit = network['max_address'] if max_address is None else max_address
        limit = self._limit(limit, new_range, len(connections))
        # Outside the new range the panel returns to the last host by default.
        inside = current_router and parse_address(current_router) in ip_network(new_range)
        router = router if router is not None else current_router if inside else router_address(new_range)
        router = self._host(router, new_range)
        forwards = {forward['address'] for forward in network.get('forwards') or []}
        # Forwarding rules keep their address: the range may not leave them behind.
        if moved and any(parse_address(address) not in ip_network(new_range) for address in forwards):
            raise NetworkError('forwards_outside')
        foreign = set(routes.values()) | forwards
        if router in foreign: raise NetworkError('address_in_use')

        if moved: connections = self._reassign(connections, new_range, limit, {router} | foreign)
        elif router != current_router and router in connections.values():
            raise NetworkError('address_in_use')
        routed = self._routed_updates(network['_id'], connections, network['connections'])

        server = dict(network.get('server') or dict(port=80), ip_address=router)
        changes.update(max_address=limit, server=server)
        after = dict(before, network_range=new_range, max_address=limit, router=router)
        if 'name' in changes: after['name'] = changes['name'] or ''
        if internet is not None: after['internet'] = internet
        if dns is not None: after['dns'] = changes['dns']
        if moved:
            subnet_mask = network_properties(new_range)[1]
            changes.update(network_range=new_range, subnet_mask=subnet_mask, connections=connections)
        Network(self.networks, network['_id']).update(**changes)
        for other_id, other_routes in routed.items():
            Network(self.networks, other_id).update(routes=other_routes)
        # A new range, panel, internet access or DNS changes everyone's configuration here.
        changed = moved or router != current_router or opened
        members = list(network['connections']) + list(routes) if changed else []
        # The answer names the new panel address: the old one may stop answering.
        result = dict(router=router, network_range=new_range)
        effects = dict(result=result, disconnect=[ObjectId(account_id) for account_id in members])
        effects['event'] = dict(kind='network_updated', network_id=network['_id'],
                                changes=[key for key in after if after[key] != before[key]],
                                internet=after['internet'])
        if moved or router != current_router: effects['panel'] = ('move', network['_id'])
        return effects

    @serialized
    def delete(self, actor_id, organization_id, network_id, confirm: bool = False) -> dict:
        self._allow(actor_id, organization_id, 'networks:delete', network_id)
        network = self._network(organization_id, network_id)
        if len(self._organization_networks(organization_id)) < 2: raise NetworkError('last_network')
        # Members move to their next network; without one they leave the organization.
        members = list(network['connections']) + list(network['routes'])
        plans = [self._detach(organization_id, network['_id'], account_id) for account_id in members]
        leaving = [plan for plan in plans if plan['leaves']]
        if leaving and not confirm:
            raise Confirmation([self._describe(plan['account_id']) for plan in leaving])
        for plan in plans: self._apply_detach(organization_id, plan)
        Network(self.networks, network['_id']).delete()
        kick = [plan['account_id'] for plan in leaving]
        disconnect = [plan['account_id'] for plan in plans if not plan['leaves']]
        event = dict(kind='network_deleted', level='WARN', name=network.get('name'),
                     network_range=network['network_range'], moved=len(disconnect), left=len(kick))
        return dict(result=None, disconnect=disconnect, kick=kick, panel=('remove', network['_id']), event=event)

    # ---------- Speed limits ----------

    def _limits_document(self, organization_id, network_id):
        # A network keeps its limits; the internet ones belong to the organization.
        if network_id is None:
            return (Organization(self.database['organizations'], organization_id).get() or {}).get('internet_limits')
        return self._network(organization_id, network_id).get('limits')

    def _check_owner(self, actor, organization_id, kind: str, owner_id) -> dict:
        # The role or person a limit is about; nobody acts on more access than its own.
        if kind not in ('role', 'account') or not ObjectId.is_valid(owner_id.__str__()):
            raise NetworkError('invalid_limits')
        if kind == 'account':
            try: self.organizations._target(actor, organization_id, ObjectId(owner_id.__str__()))
            except ValueError: raise NetworkError('account_not_found')
            return self._describe(ObjectId(owner_id.__str__()))
        role = Role(self.organizations.roles, owner_id).get()
        if not role or role['organization_id'] != organization_id: raise NetworkError('invalid_limits')
        held = Permissions(role.get('permissions', {}), administrator=bool(role.get('administrator')))
        if not actor.contains(held): raise PermissionError('The role exceeds your permissions')
        return dict(role_id=role['_id'].__str__(), name=role['name'])

    def extras(self, organization_id, network_id, period: str) -> list:
        # Worker thread: this month's extras of a network, or of the internet.
        scope = 'internet' if network_id is None else self._network(organization_id, network_id)['_id'].__str__()
        rows = []
        for document in self.database['usage'].find(dict(organization_id=organization_id.__str__(), scope=scope,
                                                        period=period)):
            down, up = document.get('extra_down', 0), document.get('extra_up', 0)
            if not down and not up: continue
            if document.get('role_id'):
                role = Role(self.organizations.roles, document['role_id']).get() or {}
                who = dict(kind='role', id=document['role_id'], name=role.get('name'))
            else:
                person = self._describe(ObjectId(document['account_id']))
                who = dict(kind='account', id=document['account_id'], name=person['username'], email=person['email'])
            rows.append(dict(who, down=down // speed.MEGABYTE, up=up // speed.MEGABYTE))
        return sorted(rows, key=lambda row: (row['kind'] != 'role', (row['name'] or '').lower()))

    @serialized
    def grant_extra(self, actor_id, organization_id, network_id, kind: str, owner_id, down=0, up=0,
                    clear: bool = False, period: str = None) -> dict:
        # Megabytes added to a quota until the month ends; clear takes them back.
        permission = 'organization:modify' if network_id is None else 'networks:modify'
        actor = self._allow(actor_id, organization_id, permission, network_id)
        for value in (down, up):
            if type(value) is not int or not 0 <= value <= speed.MAXIMUM_QUOTA: raise NetworkError('invalid_limits')
        if not clear and not down and not up: raise NetworkError('invalid_limits')
        who = self._check_owner(actor, organization_id, kind, owner_id)
        scope = 'internet' if network_id is None else self._network(organization_id, network_id)['_id'].__str__()
        key = (organization_id.__str__(), kind, owner_id.__str__(), scope)
        query = {'organization_id': key[0], f'{kind}_id': key[2], 'scope': scope, 'period': period}
        usage = self.database['usage']
        if clear: update = {'$set': dict(extra_down=0, extra_up=0)}
        else: update = {'$inc': dict(extra_down=down * speed.MEGABYTE, extra_up=up * speed.MEGABYTE)}
        usage.update_one(query, update, upsert=True)
        stored = usage.find_one(query) or {}
        totals = [stored.get('extra_down', 0), stored.get('extra_up', 0)]
        event = dict(kind='extra_cleared' if clear else 'extra_granted', network_id=None if network_id is None else scope,
                     scope='internet' if network_id is None else 'network', down=down, up=up,
                     target=who.get('username') or who.get('name'))
        result = dict(down=totals[0] // speed.MEGABYTE, up=totals[1] // speed.MEGABYTE)
        return dict(result=result, extra=(key, totals), event=event)

    def limits(self, organization_id, network_id=None) -> dict:
        # Worker thread: every role of the organization, and the people with their own limit.
        stored = speed.validate(self._limits_document(organization_id, network_id))
        roles = sorted(self.organizations.roles.find(dict(organization_id=organization_id)),
                       key=lambda role: (not role.get('administrator'), role['name'].lower()))
        rows = [dict(role_id=role['_id'].__str__(), name=role['name'], administrator=bool(role.get('administrator')),
                     **stored['roles'].get(role['_id'].__str__(), dict.fromkeys(speed.FIELDS))) for role in roles]
        members = [dict(self._describe(ObjectId(account_id)), **values)
                   for account_id, values in stored['members'].items() if ObjectId.is_valid(account_id)]
        return dict(roles=rows, members=sorted(members, key=lambda row: (row['username'] or '').lower()))

    def consumption(self, organization_id, network_id, period: str) -> list:
        # Worker thread: this month's bytes of every member of a network, or of the
        # organization on the internet, with the quota that applies to each one.
        if network_id is None:
            scope = 'internet'
            accounts = [member['account_id'].__str__()
                        for member in self.organizations.members.find(dict(organization_id=organization_id))]
        else:
            network = self._network(organization_id, network_id)
            scope = network['_id'].__str__()
            accounts = list(network['connections']) + list(network['routes'])
        limits = speed.validate(self._limits_document(organization_id, network_id))
        organization = organization_id.__str__()
        documents = list(self.database['usage'].find(dict(organization_id=organization, scope=scope, period=period)))
        spent = {document['account_id']: document for document in documents if document.get('account_id')}
        extras = {('role', document['role_id']): document for document in documents if document.get('role_id')}
        roles = {member['account_id'].__str__(): member.get('role_id')
                 for member in self.organizations.members.find(dict(organization_id=organization_id))}
        rows = []
        for account_id in accounts:
            role_id = roles.get(account_id)
            quota = speed.resolve(limits, role_id, account_id, speed.QUOTAS)
            own, role = spent.get(account_id, {}), extras.get(('role', role_id.__str__()), {}) if role_id else {}
            extra = [own.get(field, 0) + role.get(field, 0) for field in ('extra_down', 'extra_up')]
            rows.append(dict(self._describe(ObjectId(account_id)), down=own.get('down', 0), up=own.get('up', 0),
                             quota_down=quota[0], quota_up=quota[1], extra_down=extra[0], extra_up=extra[1],
                             key=(organization, account_id, scope)))
        return rows

    @serialized
    def set_limits(self, actor_id, organization_id, network_id, limits) -> dict:
        # The network's limits need networks:modify there; the internet ones, organization:modify.
        permission = 'organization:modify' if network_id is None else 'networks:modify'
        actor = self._allow(actor_id, organization_id, permission, network_id)
        try: limits = speed.validate(limits)
        except ValueError: raise NetworkError('invalid_limits')
        before = speed.validate(self._limits_document(organization_id, network_id))
        # Only the entries that change are checked: nobody limits someone with more access.
        for group, kind in (('roles', 'role'), ('members', 'account')):
            for owner_id in set(limits[group]) | set(before[group]):
                if limits[group].get(owner_id) != before[group].get(owner_id):
                    self._check_owner(actor, organization_id, kind, owner_id)
        if network_id is None:
            Organization(self.database['organizations'], organization_id).update(internet_limits=limits)
            kind, network_id = 'internet', None
        else:
            network_id = self._network(organization_id, network_id)['_id']
            Network(self.networks, network_id).update(limits=limits)
            kind = 'network'
        event = dict(kind='limits_changed', network_id=network_id, scope=kind)
        return dict(result=None, limits=(kind, network_id, limits), event=event)

    def member_by_email(self, organization_id, email) -> dict:
        # The panel adds a person to a limits table by email.
        if type(email) is not str or not email.strip(): raise NetworkError('unknown_account')
        pattern = '^' + re.escape(email.strip()) + '$'
        account = self.accounts.find_one(dict(email={'$regex': pattern, '$options': 'i'}))
        member = account and Member(self.organizations.members).get(
            organization_id=organization_id, account_id=account['_id'])
        if not member: raise NetworkError('unknown_account')
        return dict(account_id=account['_id'].__str__(), username=account.get('username'),
                    email=account.get('email'))

    # ---------- Assignments ----------

    def assignments(self, organization_id, network_id, offset: int = 0, limit: int = PAGE) -> dict:
        # Worker thread: one row per account with its own address here, in pages.
        network = self._network(organization_id, network_id)
        ordered = sorted(network['connections'].items(), key=lambda item: int(parse_address(item[1])))
        offset, limit = max(0, offset), min(max(1, limit), MAX_PAGE)
        rows = []
        for account_id, ip_address in ordered[offset:offset + limit]:
            account = Account(self.accounts, account_id).get() or {}
            membership = account.get('networks', {}).get(network['_id'].__str__(), {})
            rows.append(dict(account_id=account_id, username=account.get('username'),
                             email=account.get('email'), ip=ip_address,
                             primary=bool(membership.get('primary'))))
        return dict(rows=rows, total=len(ordered))

    @serialized
    def add(self, actor_id, organization_id, network_id, email) -> dict:
        self._allow(actor_id, organization_id, 'addresses:add', network_id)
        network = self._network(organization_id, network_id)
        if type(email) is not str or not email.strip(): raise NetworkError('unknown_account')
        # The whole address, ignoring upper and lower case.
        pattern = '^' + re.escape(email.strip()) + '$'
        account = self.accounts.find_one(dict(email={'$regex': pattern, '$options': 'i'}))
        if not account: raise NetworkError('unknown_account')
        if network['_id'].__str__() in account.get('networks', {}):
            raise NetworkError('already_assigned')
        if len(network['connections']) >= network['max_address']: raise NetworkError('exhausted')
        ip_address = self.organizations.join(account['_id'], organization_id, network['_id'])
        event = dict(kind='address_added', network_id=network['_id'], username=account.get('username'), ip=ip_address)
        return dict(result=dict(account_id=account['_id'].__str__(), ip=ip_address), event=event)

    @serialized
    def change(self, actor_id, organization_id, network_id, account_id, ip_address,
               expected: str = None) -> dict:
        actor = self._allow(actor_id, organization_id, 'addresses:modify', network_id)
        network = self._network(organization_id, network_id)
        account_id = self._assigned(network, account_id)
        if expected is not None and network['connections'][account_id] != expected:
            raise NetworkError('changed')
        self.organizations._target(actor, organization_id, ObjectId(account_id))
        ip_address = self._host(ip_address, network['network_range'], network['max_address'])
        taken = set(network['routes'].values()) | {(network.get('server') or {}).get('ip_address')}
        taken |= {forward['address'] for forward in network.get('forwards') or []}
        taken |= {address for owner, address in network['connections'].items() if owner != account_id}
        if ip_address in taken: raise NetworkError('address_in_use')
        connections = dict(network['connections'], **{account_id: ip_address})
        routed = self._routed_updates(network['_id'], connections, network['connections'])
        Network(self.networks, network['_id']).update(connections=connections)
        for other_id, other_routes in routed.items():
            Network(self.networks, other_id).update(routes=other_routes)
        event = dict(kind='address_changed', network_id=network['_id'], ip=ip_address,
                     username=self._describe(account_id)['username'])
        return dict(result=dict(ip=ip_address), disconnect=[ObjectId(account_id)], event=event)

    @serialized
    def remove(self, actor_id, organization_id, network_id, account_id) -> dict:
        actor = self._allow(actor_id, organization_id, 'addresses:delete', network_id)
        network = self._network(organization_id, network_id)
        account_id = self._assigned(network, account_id)
        self.organizations._target(actor, organization_id, ObjectId(account_id))
        plan = self._detach(organization_id, network['_id'], account_id)
        # Without another network the removal is refused, not turned into a departure.
        if plan['leaves']: raise NetworkError('only_network')
        self._apply_detach(organization_id, plan)
        event = dict(kind='address_removed', network_id=network['_id'],
                     username=self._describe(account_id)['username'])
        return dict(result=None, disconnect=[plan['account_id']], event=event)

    # ---------- Helpers ----------

    @staticmethod
    def _editable(network: dict) -> dict:
        # The values the panel form shows, as it sends them back.
        return dict(name=network.get('name') or '', network_range=network['network_range'],
                    max_address=network['max_address'],
                    router=(network.get('server') or {}).get('ip_address') or '',
                    internet=network.get('internet') is True, dns=network.get('dns') or [])

    @staticmethod
    def _assigned(network: dict, account_id) -> str:
        account_id = account_id.__str__() if account_id is not None else ''
        if account_id not in network['connections']: raise NetworkError('account_not_found')
        return account_id

    def _describe(self, account_id) -> dict:
        account = Account(self.accounts, account_id).get() or {}
        return dict(account_id=account_id.__str__(), username=account.get('username'),
                    email=account.get('email'))

    @staticmethod
    def _reassign(connections: dict, network_range: str, limit: int, reserved: set) -> dict:
        # A new range hands out addresses again from its first host, in the old order.
        hosts = (address.__str__() for address in islice(ip_network(network_range).hosts(), limit))
        free = (address for address in hosts if address not in reserved)
        ordered = sorted(connections.items(), key=lambda item: int(parse_address(item[1])))
        result = {}
        for account_id, _ in ordered:
            address = next(free, None)
            if address is None: raise NetworkError('exhausted')
            result[account_id] = address
        return result

    def _routed_updates(self, network_id, connections: dict, before: dict) -> dict:
        # Routed networks reuse this identity: their routes follow the new address.
        updates = {}
        for account_id, address in connections.items():
            if before.get(account_id) == address: continue
            account = Account(self.accounts, account_id).get() or {}
            for other_id, membership in account.get('networks', {}).items():
                if membership.get('mode') != 'routed' or membership.get('source') != network_id.__str__():
                    continue
                other = Network(self.networks, other_id).get()
                if not other: continue
                routes = updates.setdefault(other['_id'], dict(other['routes']))
                owners = {value: key for key, value in other['connections'].items()}
                owners.update({value: key for key, value in routes.items() if key != account_id})
                if owners.get(address, account_id) != account_id: raise NetworkError('address_in_use')
                routes[account_id] = address
        return updates

    def _detach(self, organization_id, network_id, account_id) -> dict:
        # Plans an account without this network: no write happens here.
        account_id = ObjectId(account_id.__str__())
        account = Account(self.accounts, account_id).get() or {}
        memberships = {key: dict(value) for key, value in account.get('networks', {}).items()}
        removed = network_id.__str__()
        primary = bool(memberships.get(removed, {}).get('primary'))
        dropped = [removed] + [key for key, value in memberships.items()
                               if value.get('mode') == 'routed' and value.get('source') == removed]
        for key in dropped: memberships.pop(key, None)
        own = [network['_id'].__str__() for network in self._organization_networks(organization_id)]
        remaining = [key for key in own if key in memberships and key not in dropped]
        assigned = [key for key in remaining if memberships[key].get('mode') == 'assigned']
        # The next network the account can use becomes its primary one.
        if primary and assigned: memberships[assigned[0]]['primary'] = True
        return dict(account_id=account_id, memberships=memberships, dropped=dropped,
                    leaves=not assigned)

    def _apply_detach(self, organization_id, plan: dict):
        account_id = plan['account_id'].__str__()
        for network_id in plan['dropped']:
            network = Network(self.networks, network_id).get()
            if not network: continue
            connections, routes = dict(network['connections']), dict(network['routes'])
            connections.pop(account_id, None), routes.pop(account_id, None)
            Network(self.networks, network_id).update(connections=connections, routes=routes)
        Account(self.accounts, plan['account_id']).update(networks=plan['memberships'])
        if not plan['leaves']: return
        member = Member(self.organizations.members).get(organization_id=organization_id,
                                                        account_id=plan['account_id'])
        if member: Member(self.organizations.members, member['_id']).delete()
