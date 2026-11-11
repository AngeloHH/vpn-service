ACTIONS = 'view', 'add', 'modify', 'delete'


class Permissions:
    # Network resources accept the primary scope; the rest are organization-wide.
    catalog = dict(status=('view',), sessions=('view', 'delete'),
                   members=ACTIONS, addresses=ACTIONS, networks=ACTIONS,
                   rules=ACTIONS, forwards=ACTIONS, roles=ACTIONS, permissions=ACTIONS,
                   organization=('view', 'modify', 'delete'))
    network_resources = 'status', 'sessions', 'members', 'addresses', 'networks', 'rules', 'forwards'
    scopes = 'all', 'primary'

    def __init__(self, *grants: dict, administrator: bool = False, primary=None):
        # Role and direct permissions merge; the broader scope wins.
        self.permissions = {}
        for grant in grants:
            for name, scope in self.validate(grant).items():
                if self.permissions.get(name) != 'all': self.permissions[name] = scope
        self.administrator = administrator
        self.primary = None if primary is None else primary.__str__()

    @classmethod
    def validate(cls, permissions: dict) -> dict:
        if type(permissions) is not dict: raise ValueError('Invalid permissions')
        for name, scope in permissions.items():
            resource, _, action = name.partition(':') if type(name) is str else ('', '', '')
            if action not in cls.catalog.get(resource, ()) or scope not in cls.scopes:
                raise ValueError(f'Invalid permission {name}')
            if scope == 'primary' and resource not in cls.network_resources:
                raise ValueError(f'{name} cannot be limited to the primary network')
        return dict(permissions)

    def allows(self, permission: str, network_id=None) -> bool:
        # The primary scope is checked where the change happens.
        if self.administrator: return True
        scope = self.permissions.get(permission)
        primary = network_id is not None and network_id.__str__() == self.primary
        return scope == 'all' or (scope == 'primary' and primary)

    def covers(self, permissions: dict, primary=None) -> bool:
        # A primary grant only stays covered inside our own primary network.
        if self.administrator: return True
        same = primary is not None and primary.__str__() == self.primary
        for name, scope in self.validate(permissions).items():
            own = self.permissions.get(name)
            if own == 'all' or (own == 'primary' and scope == 'primary' and same): continue
            return False
        return True

    def contains(self, other: 'Permissions') -> bool:
        if self.administrator: return True
        if other.administrator: return False
        return self.covers(other.permissions, other.primary)
