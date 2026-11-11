import time
from urllib.parse import parse_qs

from bson import ObjectId

from connection.database.mongodb import Account
from connection.permissions import Permissions

PAGE_SIZES = 25, 50, 75, 100


def query_of(request) -> dict:
    values = {key: items[-1] for key, items in parse_qs(request.query).items()}
    try: page = max(1, int(values.get('page', 1)))
    except ValueError: page = 1
    try: size = int(values.get('size', PAGE_SIZES[0]))
    except ValueError: size = PAGE_SIZES[0]
    return dict(page=page, size=size if size in PAGE_SIZES else PAGE_SIZES[0],
                q=values.get('q', '').strip().lower(), network=values.get('network'),
                blocked=values.get('filter') == 'blocked')


def can(actor, target, networks: list, permission: str) -> bool:
    # Allowed where the member lives, and never over someone with more access.
    permissions = actor.permissions
    if not permissions or not any(permissions.allows(permission, network) for network in networks):
        return False
    return permissions.contains(target or Permissions())


def page_of(rows: list, query: dict) -> dict:
    # Search and the network filter apply before counting the pages.
    q, network = query['q'], query['network']
    if q: rows = [row for row in rows if any(q in (row[key] or '').lower()
                                            for key in ('username', 'email', 'ip', 'id'))]
    if network: rows = [row for row in rows if network in row['networks']]
    rows.sort(key=lambda row: ((row['username'] or '').lower(), row['id']))
    start = (query['page'] - 1) * query['size']
    return dict(total=len(rows), page=query['page'], size=query['size'],
                rows=rows[start:start + query['size']])


def online_rows(vpn_server, actor, allowed) -> list:
    # Connected members come from memory: no database read per request.
    rows, now = [], time.monotonic()
    for target in vpn_server.registry.sessions.values():
        if target.organization_id != actor.organization_id or not target.networks: continue
        networks = [network.network_id.__str__() for network in target.networks.values()
                    if allowed(actor, network.network_id, 'members:view')]
        if not networks: continue
        primary = next((network for network in target.networks.values() if network.primary), None)
        # Nobody blocks or kicks their own session from the panel.
        other = target is not actor
        rows.append(dict(
            id=target.account_id.__str__(), username=target.username, email=target.email,
            ip=primary.ip_address if primary else None, networks=networks,
            online=True, blocked=False, down=target.rates[0], up=target.rates[1],
            loss=target.loss, total=target.sent + target.received,
            connected_for=int(now - (target.connected_at or now)),
            actions=dict(block=other and can(actor, target.permissions, networks, 'members:modify'),
                         kick=other and can(actor, target.permissions, networks, 'sessions:delete'))
        ))
    return rows


def read_blocked(vpn_server, organization_id):
    # Worker thread: blocked members are offline, so they live in the database.
    organizations = vpn_server.organizations
    accounts = vpn_server.table_name['accounts']

    def work() -> list:
        members = organizations.members.find(dict(organization_id=organization_id, blocked=True))
        found = []
        for member in members:
            account_id = member['account_id']
            account = Account(accounts, account_id).get() or {}
            networks = organizations.member_networks(account_id, organization_id)
            permissions = organizations.permissions(account_id, organization_id)
            found.append((account_id, account, networks, permissions))
        return found
    return work


def blocked_rows(actor, found: list, allowed) -> list:
    rows = []
    for account_id, account, networks, permissions in found:
        networks = [network.__str__() for network in networks
                    if allowed(actor, network, 'members:view')]
        if not networks: continue
        rows.append(dict(
            id=account_id.__str__(), username=account.get('username'),
            email=account.get('email'), ip=None, networks=networks, online=False,
            blocked=True, down=0, up=0, loss=0, total=0, connected_for=None,
            actions=dict(block=can(actor, permissions, networks, 'members:modify'), kick=False)
        ))
    return rows


def account_id_of(request):
    try: account_id = (request.json() or {}).get('account_id')
    except (ValueError, AttributeError): return None
    return ObjectId(account_id) if type(account_id) is str and ObjectId.is_valid(account_id) else None
