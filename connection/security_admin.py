from functools import wraps

from bson import ObjectId

from connection.database.mongodb import Account, Network, Role
from connection.network_admin import NetworkError

RULES = 100
ACTIONS, PROTOCOLS, KINDS = ('allow', 'block'), ('any', 'tcp', 'udp'), ('any', 'account', 'role')


def serialized(method):
    # The same lock as every network write.
    @wraps(method)
    def run(self, *arguments, **fields):
        with self.lock: return method(self, *arguments, **fields)
    return run


def security_of(network: dict) -> dict:
    stored = network.get('security') or {}
    return dict(isolated=stored.get('isolated') is True, rules=list(stored.get('rules') or []))


class SecurityAdmin:
    """Rules between the members of a network, as the Seguridad page edits them."""

    def __init__(self, network_admin):
        self.admin, self.lock = network_admin, network_admin.lock

    @property
    def networks(self): return self.admin.networks

    # ---------- Reading ----------

    def _label(self, side: dict) -> dict:
        # Who a side of a rule is, for the panel; a deleted role or account says so.
        if side['kind'] == 'any': return dict(side)
        if side['kind'] == 'account':
            account = Account(self.admin.accounts, side['id']).get() or {}
            return dict(side, name=account.get('username'), email=account.get('email'))
        role = Role(self.admin.organizations.roles, side['id']).get() or {}
        return dict(side, name=role.get('name'))

    def security(self, organization_id, network_id) -> dict:
        # Worker thread: the switch, the rules in order and the roles to choose from.
        network = self.admin._network(organization_id, network_id)
        security = security_of(network)
        rules = [dict(rule, source=self._label(rule['source']), destination=self._label(rule['destination']))
                 for rule in security['rules']]
        roles = sorted(self.admin.organizations.roles.find(dict(organization_id=organization_id)),
                       key=lambda role: role['name'].lower())
        return dict(isolated=security['isolated'], rules=rules,
                    roles=[dict(id=role['_id'].__str__(), name=role['name']) for role in roles])

    def table(self, organization_id) -> dict:
        # What the packet path uses: networks that are isolated or have enabled rules.
        table = {}
        for network in self.admin._organization_networks(organization_id):
            security = security_of(network)
            rules = [rule for rule in security['rules'] if rule['enabled']]
            if security['isolated'] or rules: table[network['_id']] = dict(isolated=security['isolated'], rules=rules)
        return table

    # ---------- Writing ----------

    def _side(self, actor, organization_id, side) -> dict:
        # Anyone, a person by email or id, or a role; nobody writes rules about more access than its own.
        if type(side) is not dict or side.get('kind') not in KINDS: raise NetworkError('invalid_rule')
        if side['kind'] == 'any': return dict(kind='any')
        owner = side.get('id')
        if side['kind'] == 'account' and side.get('email') is not None:
            owner = self.admin.member_by_email(organization_id, side['email'])['account_id']
        try: self.admin._check_owner(actor, organization_id, side['kind'], owner)
        except NetworkError as refused:
            raise refused if refused.code == 'account_not_found' else NetworkError('invalid_rule')
        return dict(kind=side['kind'], id=owner.__str__())

    def _may_touch(self, actor, organization_id, rule: dict):
        # The rule as it was must not be about someone with more access either;
        # a role or person that no longer exists stops nobody.
        for side in (rule['source'], rule['destination']):
            if side['kind'] == 'any': continue
            try: self.admin._check_owner(actor, organization_id, side['kind'], side['id'])
            except NetworkError: pass

    def _rule(self, actor, organization_id, body: dict) -> dict:
        action, protocol, port = body.get('action'), body.get('protocol', 'any'), body.get('port')
        if action not in ACTIONS or protocol not in PROTOCOLS: raise NetworkError('invalid_rule')
        if port is not None:
            # A port belongs to TCP or UDP.
            if type(port) is not int or not 1 <= port <= 65535: raise NetworkError('invalid_port')
            if protocol == 'any': raise NetworkError('port_needs_protocol')
        if type(body.get('enabled', True)) is not bool: raise NetworkError('invalid_rule')
        return dict(action=action, source=self._side(actor, organization_id, body.get('source')),
                    destination=self._side(actor, organization_id, body.get('destination')),
                    protocol=protocol, port=port, enabled=body.get('enabled', True))

    def _save(self, network: dict, security: dict, event: dict) -> dict:
        Network(self.networks, network['_id']).update(security=security)
        organization_id = network['organization_id']
        event = dict(event, network_id=network['_id'])
        return dict(result=None, firewall=(organization_id, self.table(organization_id)), event=event)

    def _load(self, actor_id, organization_id, network_id, permission: str):
        actor = self.admin._allow(actor_id, organization_id, permission, network_id)
        network = self.admin._network(organization_id, network_id)
        return actor, network, security_of(network)

    @staticmethod
    def _index(rules: list, rule_id) -> int:
        for index, rule in enumerate(rules):
            if rule['id'] == rule_id: return index
        raise NetworkError('rule_not_found')

    @serialized
    def set_isolated(self, actor_id, organization_id, network_id, isolated) -> dict:
        if type(isolated) is not bool: raise NetworkError('invalid_rule')
        _, network, security = self._load(actor_id, organization_id, network_id, 'rules:modify')
        security['isolated'] = isolated
        return self._save(network, security, dict(kind='isolation_changed', isolated=isolated))

    @serialized
    def add_rule(self, actor_id, organization_id, network_id, body: dict) -> dict:
        actor, network, security = self._load(actor_id, organization_id, network_id, 'rules:add')
        if len(security['rules']) >= RULES: raise NetworkError('rule_limit', maximum=RULES)
        rule = dict(id=ObjectId().__str__(), **self._rule(actor, organization_id, body))
        security['rules'].append(rule)
        effects = self._save(network, security, dict(kind='rule_added', action=rule['action']))
        effects['result'] = dict(id=rule['id'])
        return effects

    @serialized
    def update_rule(self, actor_id, organization_id, network_id, rule_id, body: dict) -> dict:
        actor, network, security = self._load(actor_id, organization_id, network_id, 'rules:modify')
        index = self._index(security['rules'], rule_id)
        self._may_touch(actor, organization_id, security['rules'][index])
        security['rules'][index] = dict(id=rule_id, **self._rule(actor, organization_id, body))
        return self._save(network, security, dict(kind='rule_changed', action=security['rules'][index]['action']))

    @serialized
    def move_rule(self, actor_id, organization_id, network_id, rule_id, step) -> dict:
        # Order decides: the first rule that matches wins.
        _, network, security = self._load(actor_id, organization_id, network_id, 'rules:modify')
        if step not in (-1, 1): raise NetworkError('invalid_rule')
        rules, index = security['rules'], self._index(security['rules'], rule_id)
        other = index + step
        if not 0 <= other < len(rules): raise NetworkError('invalid_rule')
        rules[index], rules[other] = rules[other], rules[index]
        return self._save(network, security, dict(kind='rule_moved', action=rules[other]['action']))

    @serialized
    def delete_rule(self, actor_id, organization_id, network_id, rule_id) -> dict:
        actor, network, security = self._load(actor_id, organization_id, network_id, 'rules:delete')
        index = self._index(security['rules'], rule_id)
        self._may_touch(actor, organization_id, security['rules'][index])
        rule = security['rules'].pop(index)
        return self._save(network, security, dict(kind='rule_removed', action=rule['action']))
