import re
import time
from functools import wraps
from ipaddress import ip_address as parse_address, ip_network

from bson import ObjectId

from connection import limits as speed
from connection.database.mongodb import Account, Organization
from connection.database.mongodb.methods import network_properties
from connection.forwarding import PROTOCOLS
from connection.network_admin import NetworkError
from connection.permissions import Permissions

FORMAT, VERSION = 'vpn-organization-backup', 1


def serialized(method):
    # The same lock as every network write: nothing changes halfway through a restore.
    @wraps(method)
    def run(self, *arguments, **fields):
        with self.lock: return method(self, *arguments, **fields)
    return run


def text_id(value) -> str:
    if not ObjectId.is_valid(str(value)): raise NetworkError('invalid_backup')
    return str(value)


class BackupAdmin:
    """A copy of an organization's configuration, and putting one back.

    The copy holds the networks with who has which address, the roles, the
    members with their role, own permissions and block, the limits, the rules
    between members and the forwards. Accounts and passwords belong to the
    server, not to the organization: members are found again by id or email.
    Restoring replaces everything: what the copy does not hold is removed.
    """

    def __init__(self, network_admin, access_admin, security_admin):
        self.admin, self.lock = network_admin, network_admin.lock
        self.access, self.security = access_admin, security_admin
        self.organizations, self.database = network_admin.organizations, network_admin.database

    @property
    def networks(self): return self.database['networks']

    @property
    def accounts(self): return self.database['accounts']

    # ---------- Copy ----------

    @serialized
    def export(self, actor_id, organization_id) -> dict:
        # Worker thread: the whole organization as plain JSON.
        self.admin._allow(actor_id, organization_id, 'organization:view')
        organization = Organization(self.database['organizations'], organization_id).get() or {}
        networks = self.admin._organization_networks(organization_id)
        own = {network['_id'].__str__() for network in networks}
        roles = self.organizations.roles.find(dict(organization_id=organization_id))
        members = []
        for member in self.organizations.members.find(dict(organization_id=organization_id)):
            account = Account(self.accounts, member['account_id']).get() or {}
            memberships = {key: dict(value) for key, value in (account.get('networks') or {}).items() if key in own}
            members.append(dict(account_id=member['account_id'].__str__(), username=account.get('username'),
                                email=account.get('email'), role_id=member.get('role_id') and member['role_id'].__str__(),
                                permissions=dict(member.get('permissions') or {}), blocked=bool(member.get('blocked')),
                                networks=memberships))
        return dict(
            format=FORMAT, version=VERSION, created=time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            organization=dict(name=organization.get('name'), internet_limits=speed.validate(organization.get('internet_limits'))),
            roles=[dict(id=role['_id'].__str__(), name=role['name'], permissions=dict(role.get('permissions') or {}),
                        default=bool(role.get('default')), administrator=bool(role.get('administrator')))
                   for role in roles],
            networks=[dict(id=network['_id'].__str__(), name=network.get('name'), network_range=network['network_range'],
                           max_address=network['max_address'], server=dict(network.get('server') or {}),
                           internet=network.get('internet') is True, dns=list(network.get('dns') or []),
                           connections=dict(network['connections']), routes=dict(network['routes']),
                           limits=speed.validate(network.get('limits')), forwards=list(network.get('forwards') or []),
                           security=self._check_security(network.get('security'))) for network in networks],
            members=members)

    # ---------- Checking a copy ----------

    def _check(self, organization_id, backup) -> dict:
        # Everything is checked before anything is written; any doubt refuses the whole copy.
        if type(backup) is not dict or backup.get('format') != FORMAT or backup.get('version') != VERSION:
            raise NetworkError('invalid_backup')
        for key in ('roles', 'networks', 'members'):
            if type(backup.get(key)) is not list: raise NetworkError('invalid_backup')
        try:
            roles = self._check_roles(organization_id, backup['roles'])
            networks = self._check_networks(organization_id, backup['networks'])
            organization = backup.get('organization') or {}
            if type(organization) is not dict: raise NetworkError('invalid_backup')
            internet_limits = speed.validate(organization.get('internet_limits'))
            members, skipped = self._check_members(organization_id, backup['members'], roles, networks)
        # NetworkError is a ValueError: a bad range or address is just a broken copy.
        except (AttributeError, KeyError, TypeError, ValueError): raise NetworkError('invalid_backup')
        return dict(roles=roles, networks=networks, members=members, skipped=skipped, internet_limits=internet_limits)

    def _foreign(self, collection, document_id, organization_id) -> bool:
        # An id that already belongs to another organization cannot be taken.
        found = collection.find_one({'_id': ObjectId(document_id)})
        return bool(found) and found.get('organization_id') != organization_id

    def _check_roles(self, organization_id, roles: list) -> list:
        names, result = set(), []
        for role in roles:
            role_id = text_id(role['id'])
            name = role['name']
            if type(name) is not str or not name.strip() or len(name) > 40 or name.casefold() in names:
                raise NetworkError('invalid_backup')
            names.add(name.casefold())
            if self._foreign(self.organizations.roles, role_id, organization_id): raise NetworkError('invalid_backup')
            result.append(dict(_id=ObjectId(role_id), organization_id=organization_id, name=name,
                               permissions=Permissions.validate(role['permissions']),
                               default=role['default'] is True, administrator=role['administrator'] is True))
        if sum(role['administrator'] for role in result) != 1 or sum(role['default'] for role in result) > 1:
            raise NetworkError('invalid_backup')
        return result

    def _check_networks(self, organization_id, networks: list) -> list:
        if not networks: raise NetworkError('invalid_backup')
        result, ranges = [], []
        for network in networks:
            network_id = text_id(network['id'])
            if self._foreign(self.networks, network_id, organization_id): raise NetworkError('invalid_backup')
            network_range = self.admin._range(network['network_range'])
            if any(ip_network(network_range).overlaps(other) for other in ranges): raise NetworkError('invalid_backup')
            ranges.append(ip_network(network_range))
            hosts = ip_network(network_range).num_addresses - 2
            max_address = network['max_address']
            if type(max_address) is not int or not 1 <= max_address <= hosts - 1: raise NetworkError('invalid_backup')
            server = network['server']
            router = self.admin._host(server['ip_address'], network_range)
            port = server.get('port', 80)
            if type(port) is not int or not 0 < port <= 65535: raise NetworkError('invalid_backup')
            if type(network['internet']) is not bool: raise NetworkError('invalid_backup')
            connections = {text_id(key): self.admin._host(value, network_range, max_address)
                           for key, value in network['connections'].items()}
            forwards = self._check_forwards(network.get('forwards') or [], network_range)
            used = list(connections.values()) + [router] + [forward['address'] for forward in forwards]
            if len(used) != len(set(used)): raise NetworkError('invalid_backup')
            result.append(dict(_id=ObjectId(network_id), organization_id=organization_id, name=self.admin._name(network.get('name')),
                               network_range=network_range, subnet_mask=network_properties(network_range)[1],
                               max_address=max_address, server=dict(ip_address=router, port=port),
                               internet=network['internet'], dns=self.admin._dns(network['dns']),
                               connections=connections, routes={}, limits=speed.validate(network.get('limits')),
                               forwards=forwards, security=self._check_security(network.get('security'))))
        return result

    @staticmethod
    def _check_forwards(forwards: list, network_range: str) -> list:
        # The shape of each rule; where its target leads is decided again when the table is built.
        result, keys = [], ('id', 'name', 'address', 'port', 'protocol', 'target', 'target_port', 'enabled')
        for forward in forwards:
            forward = {key: forward.get(key) for key in keys}
            forward['target'] = parse_address(forward['target']).__str__()
            address = parse_address(forward['address'])
            offset = int(address) - int(ip_network(network_range).network_address)
            if not 1 <= offset <= ip_network(network_range).num_addresses - 2: raise NetworkError('invalid_backup')
            forward['address'] = address.__str__()
            for port in (forward['port'], forward['target_port']):
                if port is not None and (type(port) is not int or not 1 <= port <= 65535): raise NetworkError('invalid_backup')
            if forward['protocol'] not in PROTOCOLS or type(forward['enabled']) is not bool or type(forward['id']) is not str:
                raise NetworkError('invalid_backup')
            result.append(forward)
        return result

    @staticmethod
    def _check_security(security) -> dict:
        if security is None: return dict(isolated=False, rules=[])
        rules = []
        for rule in security['rules']:
            for side in (rule['source'], rule['destination']):
                if side['kind'] not in ('any', 'account', 'role'): raise NetworkError('invalid_backup')
                if side['kind'] != 'any': text_id(side['id'])
            if rule['action'] not in ('allow', 'block') or rule['protocol'] not in ('any', 'tcp', 'udp'):
                raise NetworkError('invalid_backup')
            port = rule.get('port')
            if port is not None and (type(port) is not int or not 1 <= port <= 65535): raise NetworkError('invalid_backup')
            rules.append(dict(id=str(rule['id']), action=rule['action'], source=dict(rule['source']),
                              destination=dict(rule['destination']), protocol=rule['protocol'], port=port,
                              enabled=rule.get('enabled', True) is True))
        return dict(isolated=security.get('isolated') is True, rules=rules)

    def _account(self, member: dict):
        # By id on the same server; by email when the copy comes from another one.
        account = None
        if ObjectId.is_valid(str(member.get('account_id'))):
            account = Account(self.accounts, ObjectId(str(member['account_id']))).get()
        if not account and type(member.get('email')) is str and member['email'].strip():
            pattern = '^' + re.escape(member['email'].strip()) + '$'
            account = self.accounts.find_one(dict(email={'$regex': pattern, '$options': 'i'}))
        return account

    def _check_members(self, organization_id, members: list, roles: list, networks: list) -> tuple:
        role_ids = {role['_id'] for role in roles}
        network_ids = {network['_id'].__str__(): network for network in networks}
        result, skipped, seen = [], [], set()
        for member in members:
            if type(member) is not dict: raise NetworkError('invalid_backup')
            account = self._account(member)
            if not account:
                skipped.append(dict(username=member.get('username'), email=member.get('email')))
                continue
            if account['_id'] in seen: raise NetworkError('invalid_backup')
            seen.add(account['_id'])
            role_id = ObjectId(text_id(member['role_id'])) if member.get('role_id') else None
            if role_id and role_id not in role_ids: raise NetworkError('invalid_backup')
            try: permissions = Permissions.validate(member.get('permissions') or {})
            except ValueError: raise NetworkError('invalid_backup')
            memberships = member.get('networks')
            if type(memberships) is not dict or any(key not in network_ids for key in memberships):
                raise NetworkError('invalid_backup')
            assigned = [key for key, value in memberships.items() if value['mode'] == 'assigned']
            primary = [key for key in assigned if memberships[key].get('primary') is True]
            if not assigned or len(primary) != 1: raise NetworkError('invalid_backup')
            normalized = {}
            for key, value in memberships.items():
                if value['mode'] == 'assigned': normalized[key] = dict(mode='assigned', primary=key in primary)
                elif value['mode'] == 'routed' and value.get('source') in assigned and value['source'] != key:
                    normalized[key] = dict(mode='routed', source=value['source'])
                else: raise NetworkError('invalid_backup')
            result.append(dict(old_id=str(member.get('account_id')), account_id=account['_id'], role_id=role_id,
                               permissions=permissions, blocked=member.get('blocked') is True,
                               memberships=normalized,
                               username=account.get('username')))
        return result, skipped

    # ---------- Restore ----------

    def _remap(self, plan: dict):
        # A member found by email has another id here: addresses and rules follow it.
        changes = {member['old_id']: member['account_id'].__str__() for member in plan['members']
                   if member['old_id'] != member['account_id'].__str__()}
        kept = {member['account_id'].__str__() for member in plan['members']}
        for network in plan['networks']:
            network['connections'] = {changes.get(key, key): value for key, value in network['connections'].items()
                                      if changes.get(key, key) in kept}
            limits = network['limits']
            limits['members'] = {changes.get(key, key): value for key, value in limits['members'].items()}
            for rule in network['security']['rules']:
                for side in (rule['source'], rule['destination']):
                    if side['kind'] == 'account': side['id'] = changes.get(side['id'], side['id'])
        plan['internet_limits']['members'] = {changes.get(key, key): value
                                              for key, value in plan['internet_limits']['members'].items()}
        # Each member's routed address is its address in the source network.
        # An address belongs only to whoever is assigned there.
        by_id = {network['_id'].__str__(): network for network in plan['networks']}
        assigned = {(key, member['account_id'].__str__()) for member in plan['members']
                    for key, value in member['memberships'].items() if value['mode'] == 'assigned'}
        for key, network in by_id.items():
            network['connections'] = {account: value for account, value in network['connections'].items()
                                      if (key, account) in assigned}
        for member in plan['members']:
            account_id = member['account_id'].__str__()
            for key, value in member['memberships'].items():
                if value['mode'] == 'assigned' and account_id not in by_id[key]['connections']:
                    raise NetworkError('invalid_backup')
                if value['mode'] == 'routed':
                    by_id[key]['routes'][account_id] = by_id[value['source']]['connections'][account_id]

    def summary(self, organization_id, plan: dict) -> dict:
        current = {member['account_id'] for member in self.organizations.members.find(dict(organization_id=organization_id))}
        restored = {member['account_id'] for member in plan['members']}
        return dict(networks=len(plan['networks']), roles=len(plan['roles']), members=len(plan['members']),
                    skipped=plan['skipped'], leaving=len(current - restored))

    @serialized
    def restore(self, actor_id, organization_id, backup, confirm: bool = False) -> dict:
        # Only an administrator rewrites roles and permissions of everyone.
        actor = self.organizations.permissions(actor_id, organization_id)
        if not actor.administrator: raise PermissionError('Only an administrator restores a copy')
        plan = self._check(organization_id, backup)
        self._remap(plan)
        administrator = next(role['_id'] for role in plan['roles'] if role['administrator'])
        # The person restoring keeps the panel: they must stay an administrator.
        if not any(member['account_id'] == actor_id and member['role_id'] == administrator for member in plan['members']):
            raise NetworkError('backup_without_you')
        summary = self.summary(organization_id, plan)
        if not confirm: return dict(result=dict(summary, confirm=True))
        return self._apply(organization_id, plan, summary)

    def _replace(self, collection, documents: list, organization_id):
        wanted = {document['_id'] for document in documents}
        for document in collection.find(dict(organization_id=organization_id)):
            if document['_id'] not in wanted: collection.delete_one({'_id': document['_id']})
        for document in documents:
            fields = {key: value for key, value in document.items() if key != '_id'}
            if collection.find_one({'_id': document['_id']}): collection.update_one({'_id': document['_id']}, {'$set': fields})
            else: collection.insert_one(dict(document))

    def _apply(self, organization_id, plan: dict, summary: dict) -> dict:
        before_networks = [network['_id'] for network in self.admin._organization_networks(organization_id)]
        before_members = [member['account_id'] for member in self.organizations.members.find(dict(organization_id=organization_id))]
        own = {network['_id'].__str__() for network in plan['networks']} | {network_id.__str__() for network_id in before_networks}
        # Accounts lose every membership of this organization, then get the copy's.
        touched = set(before_members) | {member['account_id'] for member in plan['members']}
        for account_id in touched:
            account = Account(self.accounts, account_id).get() or {}
            memberships = {key: value for key, value in (account.get('networks') or {}).items() if key not in own}
            restored = next((member for member in plan['members'] if member['account_id'] == account_id), None)
            if restored: memberships.update(restored['memberships'])
            Account(self.accounts, account_id).update(networks=memberships)
        self._replace(self.organizations.roles, plan['roles'], organization_id)
        self._replace(self.networks, plan['networks'], organization_id)
        members = [dict(_id=existing['_id'] if existing else ObjectId(), organization_id=organization_id,
                        account_id=member['account_id'], role_id=member['role_id'], permissions=member['permissions'],
                        blocked=member['blocked'])
                   for member in plan['members']
                   for existing in [self.organizations.members.find_one(dict(organization_id=organization_id,
                                                                             account_id=member['account_id']))]]
        self._replace(self.organizations.members, members, organization_id)
        Organization(self.database['organizations'], organization_id).update(internet_limits=plan['internet_limits'])
        restored = [network['_id'] for network in plan['networks']]
        panels = [('remove', network_id) for network_id in before_networks if network_id not in restored]
        panels += [('move' if network_id in before_networks else 'add', network_id) for network_id in restored]
        staying = {member['account_id'] for member in plan['members']}
        event = dict(kind='backup_restored', level='WARN', networks=summary['networks'], members=summary['members'])
        return dict(result=dict(summary, restored=True), panels=panels, event=event,
                    forwards=(organization_id, self.access.table(organization_id)),
                    firewall=(organization_id, self.security.table(organization_id)),
                    kick=[account_id for account_id in before_members if account_id not in staying],
                    disconnect=list(staying))
