import json
import logging
import math
from http.cookies import CookieError, SimpleCookie
from urllib.parse import parse_qs

from bson import ObjectId

from connection import srp

from connection.admin.members import (account_id_of, blocked_rows, can, online_rows,
                                      page_of, query_of, read_blocked)
from connection.admin.networks import read_networks, visible
from connection.database.exceptions import AddressConflict
from connection.database.mongodb import Account
from connection.admin import diagnostics
from connection.events import INFO, WARN
from connection.network_admin import PAGE, Confirmation, NetworkError
from connection.permissions import Permissions
from connection.virtual_http import (Deferred, EventStream, HTTPRequest, HTTPResponse,
                                     VirtualHTTPServer)

COOKIE, CSRF = 'vpn_panel', 'vpn-panel'
logger = logging.getLogger(__name__)
COOKIE_FLAGS = 'HttpOnly; SameSite=Strict; Path=/'


def json_response(content: dict = None, status: int = 200,
                  headers: dict = None) -> HTTPResponse:
    headers = {'Content-Type': 'application/json', 'Cache-Control': 'no-store',
               **(headers or {})}
    body = b'' if content is None else json.dumps(content, separators=(',', ':'))
    return HTTPResponse(body, status, headers)


def error(status: int, message: str, **fields) -> HTTPResponse:
    return json_response(dict(error=message, **fields), status)


def number(value, default: int) -> int:
    try: return int(value)
    except (TypeError, ValueError): return default


def token_of(request: HTTPRequest):
    cookies = SimpleCookie()
    try: cookies.load(request.header('cookie') or '')
    except CookieError: return None
    morsel = cookies.get(COOKIE)
    return morsel.value if morsel else None


def allowed(session, network_id, permission: str) -> bool:
    permissions = session.permissions if session else None
    return bool(permissions and permissions.allows(permission, network_id))


def connected(vpn_server, request: HTTPRequest):
    # The tunnel proved the source address; the Host check stops DNS rebinding.
    client = request.client or (None, 0)
    session = vpn_server.registry.get_route(request.network_id, client[0])
    network = session.networks.get(request.network_id) if session else None
    host = (request.header('host') or '').rsplit(':', 1)[0]
    if not network or not network.server or host != network.server['ip_address']:
        return None
    return session


def access(vpn_server, request: HTTPRequest, permission: str = None,
           write: bool = False) -> tuple:
    # Writes need a header other sites cannot send without a CORS preflight.
    session = connected(vpn_server, request)
    if not session: return None, error(403, 'Forbidden')
    if write and request.header('x-requested-with') != CSRF:
        return None, error(403, 'Forbidden')
    if not vpn_server.web_sessions.valid(token_of(request), session):
        return None, error(401, 'Login required')
    if permission and not allowed(session, request.network_id, permission):
        return None, error(403, 'Forbidden')
    return session, None


def register_api(http: VirtualHTTPServer, vpn_server, interval: float = 1,
                 refresh: float = 5):
    web, streams = vpn_server.web_sessions, []
    # The latest network list per organization; streams receive it on change.
    networks_cache = {}
    collection = vpn_server.table_name['networks']

    def store(organization_id, networks) -> bool:
        changed = networks_cache.get(organization_id) != networks
        networks_cache[organization_id] = networks
        return changed

    def push_networks(organization_id, latest: bool = True):
        networks = networks_cache.get(organization_id)
        if networks is None: return
        for stream, session, _, _ in streams:
            if session.organization_id != organization_id: continue
            stream.event('networks', visible(session, networks, allowed), latest=latest)

    def reload_networks(organization_id):
        def finish(networks):
            if store(organization_id, networks): push_networks(organization_id)
            return ''
        http.submit(Deferred(read_networks(collection, organization_id), finish))

    @http.route('GET', '/api/me')
    def me(request: HTTPRequest):
        session = connected(vpn_server, request)
        if not session: return error(403, 'Forbidden')
        router = session.networks[request.network_id].server['ip_address']
        content = dict(username=session.username, email=session.email,
                       router=router, logged_in=False, internet=vpn_server.internet)
        if not web.valid(token_of(request), session): return json_response(content)
        permissions = session.permissions
        content.update(logged_in=True,
                       administrator=bool(permissions and permissions.administrator),
                       primary=permissions.primary if permissions else None,
                       permissions=permissions.permissions if permissions else {})
        return json_response(content)

    @http.route('POST', '/api/login')
    def login(request: HTTPRequest):
        session = connected(vpn_server, request)
        if not session or request.header('x-requested-with') != CSRF:
            return error(403, 'Forbidden')
        try: password = (request.json() or {}).get('password')
        except (ValueError, AttributeError): password = None
        if type(password) is not str or not password: return error(400, 'Password required')
        account_id = session.account_id
        # One attempt at a time, so parallel requests cannot skip the delay.
        wait = web.blocked(account_id)
        if wait or account_id in web.checking:
            return error(429, 'Too many attempts', retry_after=math.ceil(wait) or 1)
        web.checking.add(account_id)
        collection = vpn_server.table_name['accounts']

        def check():
            # Worker thread: the database read and the stretched check stay off the loop.
            try:
                account = Account(collection, account_id).get() or {}
                return srp.check(password, account.get('srp'))
            except Exception:
                logger.exception('Password check failed')
                return None

        def finish(correct) -> HTTPResponse:
            web.checking.discard(account_id)
            current = vpn_server.registry.get_session(session.cipher.session_id)
            if current is not session: return error(401, 'The VPN session ended')
            # An unavailable database is not counted as a wrong password.
            if correct is None: return error(503, 'Try again later')
            events, organization_id = vpn_server.events, session.organization_id
            if not correct:
                wait = web.failed(account_id)
                events.record(organization_id, WARN, 'login_failed', username=session.username,
                              wait=math.ceil(wait) or None)
                return error(401, 'Incorrect password', retry_after=math.ceil(wait) or None)
            events.record(organization_id, INFO, 'panel_login', username=session.username)
            cookie = f'{COOKIE}={web.create(session)}; {COOKIE_FLAGS}'
            return json_response(None, 204, {'Set-Cookie': cookie})

        return Deferred(check, finish)

    @http.route('POST', '/api/logout')
    def logout(request: HTTPRequest):
        if request.header('x-requested-with') != CSRF: return error(403, 'Forbidden')
        web.remove(token_of(request))
        cookie = f'{COOKIE}=; {COOKIE_FLAGS}; Max-Age=0'
        return json_response(None, 204, {'Set-Cookie': cookie})

    @http.route('GET', '/api/networks')
    def networks(request: HTTPRequest):
        session, response = access(vpn_server, request)
        if response: return response
        organization_id = session.organization_id

        def finish(networks):
            if store(organization_id, networks): push_networks(organization_id)
            current = vpn_server.registry.get_session(session.cipher.session_id)
            if current is not session: return error(401, 'The VPN session ended')
            return json_response(dict(networks=visible(session, networks, allowed)))

        return Deferred(read_networks(collection, organization_id), finish)

    def network_write(request: HTTPRequest, operation):
        # Checked and written on a worker; sessions and panels change on the loop.
        session, response = access(vpn_server, request, write=True)
        if response: return response
        try: body = request.json()
        except ValueError: body = None
        if type(body) is not dict: return error(400, 'Invalid change', code='invalid_request')
        organization_id = session.organization_id

        def work():
            try: return 200, operation(session.account_id, organization_id, body)
            except PermissionError: return 403, None
            except Confirmation as pending: return 409, pending.accounts
            except NetworkError as invalid: return 400, invalid
            except AddressConflict: return 400, NetworkError('address_in_use')
            except (ValueError, TypeError): return 400, NetworkError('invalid_request')

        def finish(result):
            status, value = result
            if status == 403: return error(403, 'Forbidden')
            if status == 409: return error(409, 'Confirmation required', accounts=value)
            if status == 400: return error(400, 'Invalid change', code=value.code, **value.fields)
            vpn_server.apply_change(dict(value, organization_id=organization_id))
            event = dict(value.get('event') or {})
            if event:
                level, kind = event.pop('level', INFO), event.pop('kind')
                vpn_server.events.record(organization_id, level, kind, event.pop('network_id', None),
                                         by=session.username, **event)
            reload_networks(organization_id)
            return json_response(value.get('result') or {})

        return Deferred(work, finish)

    admin, roles_admin, access_admin = vpn_server.network_admin, vpn_server.role_admin, vpn_server.access_admin
    security_admin, backup_admin = vpn_server.security_admin, vpn_server.backup_admin
    # Network writes can move a forwarding rule's target: they rebuild the table too.
    tabled = lambda organization, write: access_admin.with_table(organization, write)
    write_routes = {
        '/api/networks/create': lambda actor, organization, body: tabled(organization, lambda: admin.create(
            actor, organization, body.get('network_range'), body.get('max_address'), body.get('name'))),
        '/api/networks/update': lambda actor, organization, body: tabled(organization, lambda: admin.update(
            actor, organization, body.get('network_id'), name=body.get('name'),
            network_range=body.get('network_range'), max_address=body.get('max_address'),
            router=body.get('router'), internet=body.get('internet'), dns=body.get('dns'),
            expected=body.get('expected'))),
        '/api/networks/delete': lambda actor, organization, body: tabled(organization, lambda: admin.delete(
            actor, organization, body.get('network_id'), body.get('confirm') is True)),
        '/api/assignments/add': lambda actor, organization, body: admin.add(
            actor, organization, body.get('network_id'), body.get('email')),
        '/api/assignments/update': lambda actor, organization, body: admin.change(
            actor, organization, body.get('network_id'), body.get('account_id'), body.get('ip'),
            body.get('expected')),
        '/api/assignments/delete': lambda actor, organization, body: admin.remove(
            actor, organization, body.get('network_id'), body.get('account_id')),
        # network_id null: the organization's internet limits.
        '/api/limits': lambda actor, organization, body: admin.set_limits(
            actor, organization, body.get('network_id'), body.get('limits')),
        # Megabytes until the month ends, for a role or a person.
        '/api/limits/extra': lambda actor, organization, body: admin.grant_extra(
            actor, organization, body.get('network_id'), body.get('kind'), body.get('id'),
            body.get('down', 0), body.get('up', 0), body.get('clear') is True, vpn_server.usage.period),
        '/api/roles/create': lambda actor, organization, body: roles_admin.create(
            actor, organization, body.get('name'), body.get('permissions'), body.get('default') is True),
        '/api/roles/update': lambda actor, organization, body: roles_admin.update(
            actor, organization, body.get('role_id'), body.get('name'), body.get('permissions'), body.get('default')),
        '/api/roles/delete': lambda actor, organization, body: roles_admin.delete(
            actor, organization, body.get('role_id')),
        # role_id null: the member keeps only its own permissions.
        '/api/roles/assign': lambda actor, organization, body: roles_admin.assign(
            actor, organization, body.get('account_id'), body.get('role_id')),
        # The member's own permissions become exactly the ones sent.
        '/api/roles/permissions': lambda actor, organization, body: roles_admin.set_permissions(
            actor, organization, body.get('account_id'), body.get('permissions')),
        # A member enters this network with the address it has in source_id.
        '/api/routes/add': lambda actor, organization, body: access_admin.add_route(
            actor, organization, body.get('network_id'), body.get('email'), body.get('source_id')),
        '/api/routes/delete': lambda actor, organization, body: access_admin.remove_route(
            actor, organization, body.get('network_id'), body.get('account_id')),
        '/api/forwards/add': lambda actor, organization, body: access_admin.add_forward(
            actor, organization, body.get('network_id'), body),
        '/api/forwards/update': lambda actor, organization, body: access_admin.update_forward(
            actor, organization, body.get('network_id'), body.get('id'), body),
        '/api/forwards/delete': lambda actor, organization, body: access_admin.delete_forward(
            actor, organization, body.get('network_id'), body.get('id')),
        # Seguridad: rules between the members of a network, read top to bottom.
        '/api/security/isolated': lambda actor, organization, body: security_admin.set_isolated(
            actor, organization, body.get('network_id'), body.get('isolated')),
        '/api/security/rules/add': lambda actor, organization, body: security_admin.add_rule(
            actor, organization, body.get('network_id'), body),
        '/api/security/rules/update': lambda actor, organization, body: security_admin.update_rule(
            actor, organization, body.get('network_id'), body.get('id'), body),
        '/api/security/rules/move': lambda actor, organization, body: security_admin.move_rule(
            actor, organization, body.get('network_id'), body.get('id'), body.get('step')),
        '/api/security/rules/delete': lambda actor, organization, body: security_admin.delete_rule(
            actor, organization, body.get('network_id'), body.get('id')),
        # The whole organization becomes the copy; without confirm only the summary comes back.
        '/api/backup/restore': lambda actor, organization, body: backup_admin.restore(
            actor, organization, body.get('backup'), body.get('confirm') is True),
    }
    for path, operation in write_routes.items():
        http.add_route('POST', path, lambda request, operation=operation: network_write(request, operation))

    def limits_scope(session, query: dict):
        # ('view', 'edit') permissions of a network's limits, or of the internet ones.
        network_id = query.get('network') or None
        if network_id: return network_id, allowed(session, network_id, 'networks:view'), allowed(session, network_id, 'networks:modify')
        return None, allowed(session, None, 'organization:view'), allowed(session, None, 'organization:modify')

    @http.route('GET', '/api/usage')
    def consumption(request: HTTPRequest):
        # This month's consumption per person: of a network, or of the internet without one.
        session, response = access(vpn_server, request)
        if response: return response
        query = {key: values[-1] for key, values in parse_qs(request.query).items()}
        network_id, view, _ = limits_scope(session, query)
        if not view: return error(403, 'Forbidden')
        offset, limit = number(query.get('offset'), 0), min(max(1, number(query.get('limit'), PAGE)), 500)
        organization_id, usage = session.organization_id, vpn_server.usage
        period = usage.period

        def work():
            try: return admin.consumption(organization_id, network_id, period)
            except NetworkError: return None

        def finish(rows):
            if rows is None: return error(404, 'Not found', code='network_not_found')
            for row in rows:
                # Counters in memory are ahead of MongoDB by up to a few seconds.
                counter = usage.totals.get(row.pop('key')) if usage.period == period else None
                if counter: row['down'], row['up'] = counter
            rows.sort(key=lambda row: (-(row['down'] + row['up']), (row['username'] or '').lower()))
            return json_response(dict(rows=rows[max(0, offset):max(0, offset) + limit], total=len(rows), period=period))

        return Deferred(work, finish)

    @http.route('GET', '/api/limits')
    def limits(request: HTTPRequest):
        session, response = access(vpn_server, request)
        if response: return response
        query = {key: values[-1] for key, values in parse_qs(request.query).items()}
        network_id, view, edit = limits_scope(session, query)
        if not view: return error(403, 'Forbidden')
        organization_id = session.organization_id

        period = vpn_server.usage.period

        def work():
            try: return dict(admin.limits(organization_id, network_id),
                             extras=admin.extras(organization_id, network_id, period))
            except NetworkError: return None

        def finish(content):
            if content is None: return error(404, 'Not found', code='network_not_found')
            return json_response(dict(content, can_edit=edit))

        return Deferred(work, finish)

    @http.route('GET', '/api/limits/member')
    def limits_member(request: HTTPRequest):
        # Finds a member by email to give it its own limit.
        session, response = access(vpn_server, request)
        if response: return response
        query = {key: values[-1] for key, values in parse_qs(request.query).items()}
        if not limits_scope(session, query)[2]: return error(403, 'Forbidden')
        organization_id, email = session.organization_id, query.get('email')

        def work():
            try: return admin.member_by_email(organization_id, email)
            except NetworkError: return None

        def finish(member):
            if member is None: return error(404, 'Not found', code='unknown_account')
            return json_response(member)

        return Deferred(work, finish)

    @http.route('GET', '/api/roles')
    def roles(request: HTTPRequest):
        # Names are enough to assign roles; their permissions need roles:view.
        session, response = access(vpn_server, request)
        if response: return response
        view = allowed(session, None, 'roles:view')
        if not view and not allowed(session, None, 'permissions:view'): return error(403, 'Forbidden')
        organization_id = session.organization_id

        def finish(rows):
            own = session.permissions
            for row in rows:
                # Nobody changes a role holding anything they do not hold.
                editable = not row['administrator'] and own.covers(row['permissions'])
                row['actions'] = dict(modify=editable and allowed(session, None, 'roles:modify'),
                                      delete=editable and allowed(session, None, 'roles:delete'))
                if not view: row.pop('permissions')
            # The catalog travels with the roles, so the panel never keeps its own copy.
            return json_response(dict(roles=rows, can_add=allowed(session, None, 'roles:add'),
                                      catalog=Permissions.catalog, network_resources=Permissions.network_resources))

        return Deferred(lambda: roles_admin.overview(organization_id), finish)

    @http.route('GET', '/api/roles/members')
    def role_members(request: HTTPRequest):
        session, response = access(vpn_server, request, 'permissions:view')
        if response: return response
        query = query_of(request)
        organization_id = session.organization_id
        visible = lambda network_id: allowed(session, network_id, 'members:view')

        def work():
            return roles_admin.member_list(organization_id, visible, query), roles_admin.overview(organization_id)

        def finish(found):
            page, roles = found
            own = session.permissions
            for row in page['rows']:
                held = row.pop('held')
                contained = own.contains(held)
                # Roles this viewer may give to this member; the administrator one only by an administrator.
                assignable = [role['role_id'] for role in roles
                              if (own.administrator if role['administrator'] else own.covers(role['permissions'], held.primary))]
                row.update(primary=held.primary, me=row['account_id'] == session.account_id.__str__(),
                           actions=dict(assign=contained and allowed(session, None, 'permissions:modify'),
                                        grant=contained and allowed(session, None, 'permissions:add'),
                                        revoke=contained and allowed(session, None, 'permissions:delete')),
                           roles=assignable)
            return json_response(page)

        return Deferred(work, finish)

    @http.route('GET', '/api/backup')
    def backup(request: HTTPRequest):
        # The organization's configuration as a file; never accounts or passwords.
        session, response = access(vpn_server, request)
        if response: return response
        organization_id, account_id = session.organization_id, session.account_id

        def work():
            try: return backup_admin.export(account_id, organization_id)
            except PermissionError: return None

        def finish(copy):
            if copy is None: return error(403, 'Forbidden')
            return json_response(copy)

        return Deferred(work, finish)

    @http.route('GET', '/api/security')
    def security(request: HTTPRequest):
        session, response = access(vpn_server, request)
        if response: return response
        query = {key: values[-1] for key, values in parse_qs(request.query).items()}
        network_id = query.get('network', '')
        if not allowed(session, network_id, 'rules:view'): return error(403, 'Forbidden')
        organization_id = session.organization_id

        def work():
            try: return security_admin.security(organization_id, network_id)
            except NetworkError: return None

        def finish(found):
            if found is None: return error(404, 'Not found', code='network_not_found')
            found['can'] = {name: allowed(session, network_id, name)
                            for name in ('rules:add', 'rules:modify', 'rules:delete')}
            return json_response(found)

        return Deferred(work, finish)

    @http.route('GET', '/api/access')
    def network_access(request: HTTPRequest):
        # Routes need addresses:view in the network; forwards, forwards:view.
        session, response = access(vpn_server, request)
        if response: return response
        query = {key: values[-1] for key, values in parse_qs(request.query).items()}
        network_id = query.get('network', '')
        see_routes, see_forwards = (allowed(session, network_id, name) for name in ('addresses:view', 'forwards:view'))
        if not see_routes and not see_forwards: return error(403, 'Forbidden')
        organization_id, organizations = session.organization_id, vpn_server.organizations

        def work():
            try:
                routes = access_admin.routes(organization_id, network_id) if see_routes else None
                forwards = access_admin.forwards(organization_id, network_id) if see_forwards else None
            except NetworkError: return None
            for row in routes or []:
                try: row['permissions'] = organizations.permissions(ObjectId(row['account_id']), organization_id)
                except PermissionError: row['permissions'] = None
            return routes, forwards

        def finish(found):
            if found is None: return error(404, 'Not found', code='network_not_found')
            routes, forwards = found
            for row in routes or []:
                target = row.pop('permissions')
                row['online'] = bool(vpn_server.registry.get_account(ObjectId(row['account_id'])))
                row['actions'] = dict(delete=bool(target) and session.permissions.contains(target)
                                      and allowed(session, network_id, 'addresses:delete'))
            can = {name: allowed(session, network_id, name)
                   for name in ('addresses:add', 'forwards:add', 'forwards:modify', 'forwards:delete')}
            return json_response(dict(routes=routes, forwards=forwards, can=can,
                                      internet=vpn_server.internet))

        return Deferred(work, finish)

    @http.route('GET', '/api/assignments')
    def assignments(request: HTTPRequest):
        session, response = access(vpn_server, request)
        if response: return response
        query = {key: values[-1] for key, values in parse_qs(request.query).items()}
        network_id = query.get('network', '')
        if not allowed(session, network_id, 'addresses:view'): return error(403, 'Forbidden')
        offset, limit = number(query.get('offset'), 0), number(query.get('limit'), PAGE)
        organization_id, organizations = session.organization_id, vpn_server.organizations

        def work():
            # Worker thread: the rows and each member's permissions come from MongoDB.
            try: page = admin.assignments(organization_id, network_id, offset, limit)
            except NetworkError: return None
            for row in page['rows']:
                try: row['permissions'] = organizations.permissions(ObjectId(row['account_id']), organization_id)
                except PermissionError: row['permissions'] = None
            return page

        def finish(page):
            if page is None: return error(404, 'Not found', code='network_not_found')
            for row in page['rows']:
                # Nobody changes the address of someone with more access.
                target = row.pop('permissions')
                contained = bool(target) and session.permissions.contains(target)
                row['online'] = bool(vpn_server.registry.get_account(ObjectId(row['account_id'])))
                row['actions'] = dict(
                    modify=contained and allowed(session, network_id, 'addresses:modify'),
                    delete=contained and allowed(session, network_id, 'addresses:delete'))
            return json_response(page)

        return Deferred(work, finish)

    @http.route('GET', '/api/members')
    def members(request: HTTPRequest):
        session, response = access(vpn_server, request)
        if response: return response
        query = query_of(request)
        if not query['blocked']: return json_response(page_of(online_rows(vpn_server, session, allowed), query))

        def finish(found):
            rows = blocked_rows(session, found, allowed)
            return json_response(page_of(rows, query))

        return Deferred(read_blocked(vpn_server, session.organization_id), finish)

    @http.route('GET', '/api/members/ports')
    def member_ports(request: HTTPRequest):
        # Estado's back panel: every connected member, oldest connection first, so ports stay put.
        session, response = access(vpn_server, request)
        if response: return response
        rows = online_rows(vpn_server, session, allowed)
        rows.sort(key=lambda row: (-row['connected_for'], row['id']))
        keys = 'id', 'username', 'email', 'ip', 'networks', 'connected_for'
        return json_response(dict(rows=[{key: row[key] for key in keys} for row in rows]))

    @http.route('POST', '/api/members/block')
    def block(request: HTTPRequest):
        session, response = access(vpn_server, request, write=True)
        if response: return response
        target_id = account_id_of(request)
        try: blocked = bool((request.json() or {}).get('blocked'))
        except (ValueError, AttributeError): blocked = None
        if not target_id or blocked is None: return error(400, 'Invalid member')
        if target_id == session.account_id: return error(400, 'You cannot block yourself')
        organizations, organization_id = vpn_server.organizations, session.organization_id

        def work():
            # Worker thread: the permission check and the write use the database.
            try: organizations.set_blocked(session.account_id, organization_id, target_id, blocked)
            except PermissionError as denied: return 403, str(denied)
            except ValueError as invalid: return 404, str(invalid)
            account = Account(vpn_server.table_name['accounts'], target_id).get() or {}
            return 204, account.get('username')

        def finish(result):
            status, message = result
            if status != 204: return error(status, message)
            kind = 'member_blocked' if blocked else 'member_unblocked'
            vpn_server.events.record(organization_id, WARN, kind, username=message, by=session.username)
            # Written first, then the live session ends: the order we agreed on.
            if blocked: vpn_server.kick(target_id)
            return json_response(None, 204)

        return Deferred(work, finish)

    @http.route('POST', '/api/sessions/kick')
    def kick(request: HTTPRequest):
        session, response = access(vpn_server, request, write=True)
        if response: return response
        target_id = account_id_of(request)
        target = vpn_server.registry.get_account(target_id) if target_id else None
        if not target or target.organization_id != session.organization_id:
            return error(404, 'The member is not connected')
        if target is session: return error(400, 'You cannot kick yourself')
        networks = [network.network_id for network in target.networks.values()]
        if not can(session, target.permissions, networks, 'sessions:delete'):
            return error(403, 'Forbidden')
        vpn_server.events.record(session.organization_id, WARN, 'member_kicked',
                                 username=target.username, by=session.username)
        vpn_server.kick(target_id)
        return json_response(None, 204)

    @http.route('GET', '/api/logs')
    def logs(request: HTTPRequest):
        session, response = access(vpn_server, request)
        if response: return response
        visible = vpn_server.events.visible(
            session.organization_id, lambda network_id: allowed(session, network_id, 'status:view'))
        return json_response(dict(events=visible))

    @http.route('POST', '/api/diagnostics')
    def diagnose(request: HTTPRequest):
        # Tests run from the server, so they need status:view over everything.
        session, response = access(vpn_server, request, write=True)
        if response: return response
        if not allowed(session, None, 'status:view'): return error(403, 'Forbidden')
        try: parsed = diagnostics.request_of(request.json())
        except ValueError: parsed = None
        if not parsed: return error(400, 'Invalid test')
        return Deferred(lambda: diagnostics.run(*parsed), json_response)

    @http.route('GET', '/api/status')
    def status(request: HTTPRequest):
        session, response = access(vpn_server, request, 'status:view')
        if response: return response
        network = session.networks[request.network_id]
        return json_response(vpn_server.status(network.organization_id))

    @http.route('GET', '/api/events')
    def events(request: HTTPRequest):
        session, response = access(vpn_server, request, 'status:view')
        if response: return response
        stream = EventStream()
        streams.append((stream, session, request.network_id, token_of(request)))
        network = session.networks[request.network_id]
        stream.event('status', vpn_server.status(network.organization_id))
        networks = networks_cache.get(session.organization_id)
        if networks is None: reload_networks(session.organization_id)
        else: stream.event('networks', visible(session, networks, allowed))
        return stream

    @http.every(interval)
    def publish():
        # A stream ends with its login, its VPN session or its permission.
        for item in list(streams):
            stream, session, network_id, token = item
            current = vpn_server.registry.get_session(session.cipher.session_id)
            network = session.networks.get(network_id)
            active = current is session and network and web.valid(token, session, False)
            if stream.closed or not active or not allowed(session, network_id, 'status:view'):
                stream.close()
                streams.remove(item)
                continue
            stream.event('status', vpn_server.status(network.organization_id), latest=True)

    @http.every(refresh)
    def refresh_networks():
        # Networks created or removed elsewhere reach open panels within seconds.
        for organization_id in {session.organization_id for _, session, _, _ in streams}:
            reload_networks(organization_id)

    http.every(60, web.cleanup)
