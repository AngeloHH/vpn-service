from bson import ObjectId

from connection.database.mongodb import Account, Member, Network, Organization, Role
from connection.permissions import Permissions


class Organizations:
    # Administrative writes stay outside the packet path; each one is checked.
    def __init__(self, database):
        self.database = database

    @property
    def roles(self): return self.database['roles']

    @property
    def members(self): return self.database['members']

    def create(self, account_id: ObjectId, name: str = None,
               network_range: str = '10.0.0.0/24', max_address: int = 253):
        # A new organization starts with its administrator and a first network.
        organization = Organization(self.database['organizations']).create(name)
        organization_id = organization['id']
        role = Role(self.roles).create(
            organization_id=organization_id, name='Administrador',
            permissions={}, default=False, administrator=True
        )
        network = Network(self.database['networks'])
        network.create(network_range, max_address, organization_id)
        Member(self.members).create(organization_id=organization_id,
                                    account_id=account_id,
                                    role_id=role['id'], permissions={})
        network.to_network(Account(self.database['accounts'], account_id), primary=True)
        return organization_id

    def join(self, account_id: ObjectId, organization_id: ObjectId,
             network_id: ObjectId) -> str:
        network = Network(self.database['networks'], network_id)
        details = network.get()
        if not details or details.get('organization_id') != organization_id:
            raise ValueError('The network does not belong to the organization')
        member = dict(organization_id=organization_id, account_id=account_id)
        # New members receive the default role; more access is granted directly.
        if not Member(self.members).get(**member):
            default = self.roles.find_one(dict(organization_id=organization_id, default=True))
            role_id = default['_id'] if default else None
            Member(self.members).create(**member, role_id=role_id, permissions={})
        primary = self.primary_network(account_id, organization_id) is None
        account = Account(self.database['accounts'], account_id)
        return network.to_network(account, primary=primary)

    def primary_network(self, account_id: ObjectId, organization_id: ObjectId):
        account = Account(self.database['accounts'], account_id).get() or {}
        for network_id, membership in account.get('networks', {}).items():
            if not membership.get('primary'): continue
            network = Network(self.database['networks'], network_id).get() or {}
            if network.get('organization_id') == organization_id: return network_id

    def member_networks(self, account_id: ObjectId, organization_id: ObjectId) -> list:
        account = Account(self.database['accounts'], account_id).get() or {}
        networks = []
        for network_id in account.get('networks', {}):
            network = Network(self.database['networks'], network_id).get() or {}
            if network.get('organization_id') == organization_id: networks.append(network_id)
        return networks

    def is_blocked(self, account_id: ObjectId, organization_id: ObjectId) -> bool:
        member = Member(self.members).get(organization_id=organization_id,
                                          account_id=account_id)
        return bool(member and member.get('blocked'))

    def set_blocked(self, actor_id: ObjectId, organization_id: ObjectId,
                    target_id: ObjectId, blocked: bool):
        # The scope applies where the member lives: one of its networks.
        actor = self.permissions(actor_id, organization_id)
        networks = self.member_networks(target_id, organization_id)
        if not any(actor.allows('members:modify', network) for network in networks):
            raise PermissionError('members:modify is not allowed')
        member, _ = self._target(actor, organization_id, target_id)
        Member(self.members, member['_id']).update(blocked=bool(blocked))

    def permissions(self, account_id: ObjectId,
                    organization_id: ObjectId) -> Permissions:
        member = Member(self.members).get(organization_id=organization_id,
                                          account_id=account_id)
        if not member: raise PermissionError('The account is not a member')
        role = Role(self.roles, member['role_id']).get() if member.get('role_id') else None
        grants = (role or {}).get('permissions', {}), member.get('permissions', {})
        administrator = bool(role and role.get('administrator'))
        primary = self.primary_network(account_id, organization_id)
        return Permissions(*grants, administrator=administrator, primary=primary)

    def _require(self, actor_id: ObjectId, organization_id: ObjectId,
                 permission: str) -> Permissions:
        actor = self.permissions(actor_id, organization_id)
        if not actor.allows(permission): raise PermissionError(f'{permission} is not allowed')
        return actor

    def _covered(self, actor: Permissions, permissions: dict, primary=None) -> dict:
        permissions = Permissions.validate(permissions)
        if not actor.covers(permissions, primary):
            raise PermissionError('The permissions exceed your own')
        return permissions

    def _role(self, actor: Permissions, organization_id: ObjectId,
              role_id: ObjectId) -> dict:
        # A role may only be changed by someone who holds all of it.
        role = Role(self.roles, role_id).get()
        if not role or role['organization_id'] != organization_id:
            raise ValueError('The role does not exist')
        if role.get('administrator'):
            raise PermissionError('The administrator role cannot be changed')
        self._covered(actor, role['permissions'])
        return role

    def _set_default(self, organization_id: ObjectId, role_id: ObjectId):
        # Only one role is assigned automatically to new members.
        query = dict(organization_id=organization_id, default=True)
        for role in list(self.roles.find(query)):
            Role(self.roles, role['_id']).update(default=False)
        Role(self.roles, role_id).update(default=True)

    def create_role(self, actor_id: ObjectId, organization_id: ObjectId,
                    name: str, permissions: dict, default: bool = False):
        actor = self._require(actor_id, organization_id, 'roles:add')
        permissions = self._covered(actor, permissions)
        role = Role(self.roles).create(
            organization_id=organization_id, name=name,
            permissions=permissions, default=False, administrator=False
        )
        if default: self._set_default(organization_id, role['id'])
        return role['id']

    def update_role(self, actor_id: ObjectId, organization_id: ObjectId,
                    role_id: ObjectId, name: str = None,
                    permissions: dict = None, default: bool = None):
        actor = self._require(actor_id, organization_id, 'roles:modify')
        self._role(actor, organization_id, role_id)
        changes = {} if name is None else dict(name=name)
        if permissions is not None:
            changes.update(permissions=self._covered(actor, permissions))
        if changes: Role(self.roles, role_id).update(**changes)
        if default is True: self._set_default(organization_id, role_id)
        if default is False: Role(self.roles, role_id).update(default=False)

    def delete_role(self, actor_id: ObjectId, organization_id: ObjectId,
                    role_id: ObjectId):
        actor = self._require(actor_id, organization_id, 'roles:delete')
        role = self._role(actor, organization_id, role_id)
        # Members of a deleted role fall back to the default role, if any.
        query = dict(organization_id=organization_id, default=True)
        default = None if role.get('default') else self.roles.find_one(query)
        role_query = dict(organization_id=organization_id, role_id=role_id)
        for member in list(self.members.find(role_query)):
            Member(self.members, member['_id']).update(
                role_id=default['_id'] if default else None
            )
        Role(self.roles, role_id).delete()

    def _target(self, actor: Permissions, organization_id: ObjectId,
                target_id: ObjectId) -> tuple:
        member = Member(self.members).get(organization_id=organization_id,
                                          account_id=target_id)
        if not member: raise ValueError('The account is not a member')
        target = self.permissions(target_id, organization_id)
        # Nobody may change a member who holds anything they do not.
        if not actor.contains(target):
            raise PermissionError('The member exceeds your permissions')
        return member, target

    def _keep_administrator(self, organization_id: ObjectId):
        query = dict(organization_id=organization_id, administrator=True)
        role = self.roles.find_one(query)
        query = dict(organization_id=organization_id, role_id=role['_id'])
        if len(list(self.members.find(query))) < 2:
            raise ValueError('The organization needs an administrator')

    def assign_role(self, actor_id: ObjectId, organization_id: ObjectId,
                    target_id: ObjectId, role_id: ObjectId = None):
        actor = self._require(actor_id, organization_id, 'permissions:modify')
        member, target = self._target(actor, organization_id, target_id)
        role = Role(self.roles, role_id).get() if role_id else None
        if role_id and (not role or role['organization_id'] != organization_id):
            raise ValueError('The role does not exist')
        administrator = bool(role and role.get('administrator'))
        if administrator and not actor.administrator:
            raise PermissionError('Only an administrator can assign that role')
        if role: self._covered(actor, role['permissions'], target.primary)
        if target.administrator and not administrator:
            self._keep_administrator(organization_id)
        Member(self.members, member['_id']).update(role_id=role_id)

    def grant(self, actor_id: ObjectId, organization_id: ObjectId,
              target_id: ObjectId, permissions: dict):
        # Granting sets the scope of each named permission.
        actor = self._require(actor_id, organization_id, 'permissions:add')
        member, target = self._target(actor, organization_id, target_id)
        permissions = self._covered(actor, permissions, target.primary)
        permissions = {**member.get('permissions', {}), **permissions}
        Member(self.members, member['_id']).update(permissions=permissions)

    def revoke(self, actor_id: ObjectId, organization_id: ObjectId,
               target_id: ObjectId, names: list[str]):
        actor = self._require(actor_id, organization_id, 'permissions:delete')
        member, _ = self._target(actor, organization_id, target_id)
        permissions = {name: scope for name, scope in member.get('permissions', {}).items()
                       if name not in names}
        Member(self.members, member['_id']).update(permissions=permissions)
