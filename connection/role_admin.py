from functools import wraps
from threading import Lock

from bson import ObjectId

from connection.database.mongodb import Account, Member, Role
from connection.events import WARN
from connection.network_admin import NetworkError
from connection.permissions import Permissions

NAME_LENGTH = 40
PAGE, MAX_PAGE = 25, 100


def serialized(method):
    @wraps(method)
    def run(self, *arguments, **fields):
        with self.lock: return method(self, *arguments, **fields)
    return run


class RoleAdmin:
    """Roles and members of an organization, as the Sistema page edits them.

    Organizations decides who may do what; this layer validates the input,
    turns refusals into codes for the panel and says whose session to refresh.
    """

    def __init__(self, organizations):
        self.organizations, self.database = organizations, organizations.database
        self.lock = Lock()

    @property
    def roles(self): return self.organizations.roles

    @property
    def members(self): return self.organizations.members

    # ---------- Reading (worker thread) ----------

    def overview(self, organization_id) -> list:
        # Every role with how many members hold it; the administrator first.
        members = list(self.members.find(dict(organization_id=organization_id)))
        rows = []
        for role in self.roles.find(dict(organization_id=organization_id)):
            count = sum(1 for member in members if member.get('role_id') == role['_id'])
            rows.append(dict(role_id=role['_id'].__str__(), name=role['name'],
                             permissions=dict(role.get('permissions', {})), default=bool(role.get('default')),
                             administrator=bool(role.get('administrator')), members=count))
        return sorted(rows, key=lambda row: (not row['administrator'], row['name'].lower()))

    def member_list(self, organization_id, visible, query: dict) -> dict:
        # Members the viewer may see in at least one of their networks, searched and paged.
        text = (query.get('q') or '').strip().lower()
        rows = []
        for member in self.members.find(dict(organization_id=organization_id)):
            account_id = member['account_id']
            networks = self.organizations.member_networks(account_id, organization_id)
            if not any(visible(network) for network in networks or [None]): continue
            account = Account(self.database['accounts'], account_id).get() or {}
            username, email = account.get('username') or '', account.get('email') or ''
            if text and text not in username.lower() and text not in email.lower(): continue
            role_id = member.get('role_id')
            rows.append(dict(account_id=account_id.__str__(), username=username, email=email,
                             role_id=role_id.__str__() if role_id else None,
                             permissions=dict(member.get('permissions', {})), blocked=bool(member.get('blocked'))))
        rows.sort(key=lambda row: (row['username'].lower(), row['email'].lower()))
        page, size = max(1, query.get('page', 1)), min(max(1, query.get('size', PAGE)), MAX_PAGE)
        start, total = (page - 1) * size, len(rows)
        rows = rows[start:start + size]
        # Only the shown page needs each member's merged permissions.
        for row in rows:
            row['held'] = self.organizations.permissions(ObjectId(row['account_id']), organization_id)
        return dict(rows=rows, total=total, page=page, size=size)

    # ---------- Roles ----------

    def _name(self, organization_id, name, own_id=None) -> str:
        if type(name) is not str or not name.strip() or len(name.strip()) > NAME_LENGTH:
            raise NetworkError('invalid_role_name')
        name = name.strip()
        for role in self.roles.find(dict(organization_id=organization_id)):
            if role['_id'] != own_id and role['name'].casefold() == name.casefold():
                raise NetworkError('role_name_taken')
        return name

    @staticmethod
    def _permissions(permissions) -> dict:
        try: return Permissions.validate(permissions)
        except ValueError: raise NetworkError('invalid_permissions')

    def _role(self, organization_id, role_id) -> dict:
        role = Role(self.roles, role_id).get() if ObjectId.is_valid(str(role_id)) else None
        if not role or role['organization_id'] != organization_id: raise NetworkError('role_not_found')
        return role

    def _editable(self, organization_id, role_id) -> dict:
        role = self._role(organization_id, role_id)
        if role.get('administrator'): raise NetworkError('role_locked')
        return role

    def _holders(self, organization_id, role_id) -> list:
        query = dict(organization_id=organization_id, role_id=role_id)
        return [member['account_id'] for member in self.members.find(query)]

    @serialized
    def create(self, actor_id, organization_id, name, permissions, default=False) -> dict:
        name, permissions = self._name(organization_id, name), self._permissions(permissions)
        role_id = self.organizations.create_role(actor_id, organization_id, name, permissions, default is True)
        return dict(result=dict(role_id=role_id.__str__()), event=dict(kind='role_created', name=name))

    @serialized
    def update(self, actor_id, organization_id, role_id, name=None, permissions=None, default=None) -> dict:
        role = self._editable(organization_id, role_id)
        if name is not None: name = self._name(organization_id, name, role['_id'])
        if permissions is not None: permissions = self._permissions(permissions)
        if default is not None and type(default) is not bool: raise NetworkError('invalid_request')
        self.organizations.update_role(actor_id, organization_id, role['_id'], name, permissions, default)
        # Its members get the new permissions and limits without reconnecting.
        event = dict(kind='role_updated', name=name or role['name'])
        return dict(result=None, refresh=self._holders(organization_id, role['_id']), event=event)

    @serialized
    def delete(self, actor_id, organization_id, role_id) -> dict:
        role = self._editable(organization_id, role_id)
        holders = self._holders(organization_id, role['_id'])
        self.organizations.delete_role(actor_id, organization_id, role['_id'])
        return dict(result=None, refresh=holders, event=dict(kind='role_deleted', level=WARN, name=role['name']))

    # ---------- Members ----------

    def _account(self, organization_id, account_id) -> ObjectId:
        if not ObjectId.is_valid(str(account_id)): raise NetworkError('account_not_found')
        account_id = ObjectId(str(account_id))
        if not Member(self.members).get(organization_id=organization_id, account_id=account_id):
            raise NetworkError('account_not_found')
        return account_id

    def _username(self, account_id) -> str:
        return (Account(self.database['accounts'], account_id).get() or {}).get('username')

    @serialized
    def assign(self, actor_id, organization_id, account_id, role_id) -> dict:
        account_id = self._account(organization_id, account_id)
        role = self._role(organization_id, role_id) if role_id else None
        try: self.organizations.assign_role(actor_id, organization_id, account_id, role and role['_id'])
        except NetworkError: raise
        except ValueError: raise NetworkError('last_administrator')
        event = dict(kind='role_assigned', username=self._username(account_id), name=(role or {}).get('name'))
        return dict(result=None, refresh=[account_id], event=event)

    @serialized
    def set_permissions(self, actor_id, organization_id, account_id, permissions) -> dict:
        # The person's own permissions become exactly these: added, changed or removed.
        account_id, permissions = self._account(organization_id, account_id), self._permissions(permissions)
        current = Member(self.members).get(organization_id=organization_id, account_id=account_id)
        current = current.get('permissions', {})
        removed = [name for name in current if name not in permissions]
        changed = {name: scope for name, scope in permissions.items() if current.get(name) != scope}
        if not removed and not changed: return dict(result=None)
        # Both halves are checked first, so a refusal never leaves half a change.
        actor = self.organizations.permissions(actor_id, organization_id)
        if removed and not actor.allows('permissions:delete'): raise PermissionError('permissions:delete')
        if changed and not actor.allows('permissions:add'): raise PermissionError('permissions:add')
        target = self.organizations.permissions(account_id, organization_id)
        if not actor.covers(changed, target.primary):
            raise PermissionError('The permissions exceed your own')
        if removed: self.organizations.revoke(actor_id, organization_id, account_id, removed)
        if changed: self.organizations.grant(actor_id, organization_id, account_id, changed)
        event = dict(kind='permissions_changed', username=self._username(account_id))
        return dict(result=None, refresh=[account_id], event=event)
