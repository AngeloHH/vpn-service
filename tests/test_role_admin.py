import unittest

from bson import ObjectId

from connection.database.mongodb import Member, Network, Role
from connection.network_admin import NetworkError
from tests.panel import Panel


class RoleAdminTest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 50000), ('127.0.0.1', 50001)

    def setUp(self):
        super().setUp()
        self.admin = self.server.role_admin
        self.administrator_role = self.collections['roles'].documents[0]['_id']

    def refused(self, code, operation, *arguments):
        with self.assertRaises(NetworkError) as raised: operation(*arguments)
        self.assertEqual(raised.exception.code, code)

    def role(self, name='Soporte', permissions=None, default=False, actor=None):
        created = self.admin.create(actor or self.owner, self.organization, name,
                                    permissions or {'members:view': 'all'}, default)
        return ObjectId(created['result']['role_id'])

    def member_of(self, account_id):
        return Member(self.collections['members']).get(organization_id=self.organization, account_id=account_id)

    def other_network(self):
        network = Network(self.collections['networks'])
        network.create('10.1.0.0/24', 253, self.organization)
        return network.id

    def test_roles_are_listed_with_their_members(self):
        support = self.role()
        self.admin.assign(self.owner, self.organization, self.member, str(support))
        rows = self.admin.overview(self.organization)
        self.assertEqual([(row['name'], row['members'], row['administrator']) for row in rows],
                         [('Administrador', 1, True), ('Soporte', 1, False)])
        self.assertEqual(rows[1]['permissions'], {'members:view': 'all'})

    def test_the_administrator_role_is_listed_first(self):
        self.role('Aaa')
        self.assertEqual([row['name'] for row in self.admin.overview(self.organization)], ['Administrador', 'Aaa'])

    def test_adding_without_removing_rights_changes_nothing(self):
        self.organizations.grant(self.owner, self.organization, self.member, {'rules:view': 'all'})
        helper = self.account('helper')
        self.organizations.join(helper, self.organization, self.network_id)
        self.organizations.grant(self.owner, self.organization, helper,
                                 {'permissions:add': 'all', 'rules:view': 'all', 'members:view': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.set_permissions(helper, self.organization, str(self.member), {'members:view': 'all'})
        self.assertEqual(self.member_of(self.member)['permissions'], {'rules:view': 'all'})

    def test_names_are_trimmed_short_and_unique_in_the_organization(self):
        self.assertEqual(Role(self.collections['roles'], self.role(' Soporte ')).get()['name'], 'Soporte')
        for name in ('', '   ', 'x' * 41, None, 5):
            self.refused('invalid_role_name', self.admin.create, self.owner, self.organization, name, {})
        self.refused('role_name_taken', self.admin.create, self.owner, self.organization, 'SOPORTE', {})
        self.refused('role_name_taken', self.admin.create, self.owner, self.organization, 'administrador', {})
        self.role('x' * 40)

    def test_a_role_may_keep_its_own_name(self):
        support = self.role()
        self.admin.update(self.owner, self.organization, str(support), name='soporte')
        self.assertEqual(Role(self.collections['roles'], support).get()['name'], 'soporte')
        self.role('Ventas')
        self.refused('role_name_taken', self.admin.update, self.owner, self.organization, str(support), 'ventas')

    def test_permissions_must_exist_in_the_catalog(self):
        for invalid in ({'members:fly': 'all'}, {'roles:view': 'primary'}, {'members:view': 'some'}, []):
            self.refused('invalid_permissions', self.admin.create, self.owner, self.organization, 'Malo', invalid)

    def test_the_administrator_role_cannot_be_edited_or_deleted(self):
        role_id = str(self.administrator_role)
        self.refused('role_locked', self.admin.update, self.owner, self.organization, role_id, 'Otro')
        self.refused('role_locked', self.admin.delete, self.owner, self.organization, role_id)
        for unknown in ('nope', str(ObjectId()), None):
            self.refused('role_not_found', self.admin.update, self.owner, self.organization, unknown, 'Otro')

    def test_roles_of_other_organizations_are_not_found(self):
        stranger = self.account('stranger')
        other = self.organizations.create(stranger)
        foreign = self.admin.create(stranger, other, 'Ajeno', {})['result']['role_id']
        self.refused('role_not_found', self.admin.delete, self.owner, self.organization, foreign)
        self.refused('role_not_found', self.admin.assign, self.owner, self.organization, str(self.member), foreign)

    def test_editing_a_role_refreshes_its_connected_members(self):
        support = self.role(permissions={'members:view': 'all'})
        self.admin.assign(self.owner, self.organization, self.member, str(support))
        self.vpn('member', self.member_address)
        session = self.server.registry.get_account(self.member)
        self.assertFalse(session.permissions.allows('roles:view'))

        change = self.admin.update(self.owner, self.organization, str(support),
                                   permissions={'roles:view': 'all'}, default=True)
        self.assertEqual(change['refresh'], [self.member])
        self.server.complete_change(dict(change, organization_id=self.organization))
        self.assertTrue(session.permissions.allows('roles:view'))
        self.assertFalse(session.permissions.allows('members:view'))
        self.assertTrue(Role(self.collections['roles'], support).get()['default'])

    def test_deleting_a_role_moves_its_members_to_the_default(self):
        support, guest = self.role(), self.role('Invitado', {}, default=True)
        self.admin.assign(self.owner, self.organization, self.member, str(support))
        change = self.admin.delete(self.owner, self.organization, str(support))
        self.assertEqual((change['refresh'], change['event']['name']), ([self.member], 'Soporte'))
        self.assertEqual(self.member_of(self.member)['role_id'], guest)

    def test_a_role_with_more_than_the_actor_holds_is_refused(self):
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'roles:add': 'all', 'roles:modify': 'all', 'members:view': 'all'})
        with self.assertRaises(PermissionError):
            self.role('Grande', {'networks:delete': 'all'}, actor=self.member)
        mine = self.role('Pequeño', {'members:view': 'all'}, actor=self.member)
        with self.assertRaises(PermissionError):
            self.admin.update(self.member, self.organization, str(mine), permissions={'rules:view': 'all'})

    def test_assigning_needs_the_permission_and_keeps_an_administrator(self):
        support = self.role()
        with self.assertRaises(PermissionError):
            self.admin.assign(self.member, self.organization, str(self.member), str(support))
        self.refused('last_administrator', self.admin.assign, self.owner, self.organization,
                     str(self.owner), str(support))
        self.refused('account_not_found', self.admin.assign, self.owner, self.organization,
                     str(ObjectId()), str(support))
        change = self.admin.assign(self.owner, self.organization, str(self.member), None)
        self.assertEqual((change['refresh'], change['event']['name']), ([self.member], None))
        self.assertIsNone(self.member_of(self.member)['role_id'])

    def test_own_permissions_become_exactly_the_ones_sent(self):
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'members:view': 'all', 'rules:view': 'primary'})
        change = self.admin.set_permissions(self.owner, self.organization, str(self.member),
                                            {'members:view': 'primary', 'roles:view': 'all'})
        self.assertEqual(self.member_of(self.member)['permissions'],
                         {'members:view': 'primary', 'roles:view': 'all'})
        self.assertEqual(change['refresh'], [self.member])
        unchanged = self.admin.set_permissions(self.owner, self.organization, str(self.member),
                                               {'members:view': 'primary', 'roles:view': 'all'})
        self.assertEqual(unchanged, dict(result=None))

    def test_a_refused_half_leaves_the_permissions_untouched(self):
        self.organizations.grant(self.owner, self.organization, self.member, {'rules:view': 'all'})
        helper = self.account('helper')
        self.organizations.join(helper, self.organization, self.network_id)
        # The helper may remove but not add.
        self.organizations.grant(self.owner, self.organization, helper,
                                 {'permissions:delete': 'all', 'rules:view': 'all', 'members:view': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.set_permissions(helper, self.organization, str(self.member), {'members:view': 'all'})
        self.assertEqual(self.member_of(self.member)['permissions'], {'rules:view': 'all'})
        # Granting what the actor does not hold is refused before anything is removed.
        self.organizations.grant(self.owner, self.organization, helper, {'permissions:add': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.set_permissions(helper, self.organization, str(self.member), {'roles:view': 'all'})
        self.assertEqual(self.member_of(self.member)['permissions'], {'rules:view': 'all'})
        self.admin.set_permissions(helper, self.organization, str(self.member), {'members:view': 'all'})
        self.assertEqual(self.member_of(self.member)['permissions'], {'members:view': 'all'})

    def test_nobody_changes_someone_with_more_access(self):
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'permissions:add': 'all', 'permissions:delete': 'all', 'rules:view': 'all'})
        self.organizations.grant(self.owner, self.organization, self.owner, {'rules:view': 'all'})
        # The owner is an administrator: even removing what the member holds is refused.
        with self.assertRaises(PermissionError):
            self.admin.set_permissions(self.member, self.organization, str(self.owner), {})

    def test_members_are_searched_paged_and_scoped(self):
        for index in range(3):
            account = self.account(f'user{index}')
            self.organizations.join(account, self.organization, self.network_id)
        everyone = self.admin.member_list(self.organization, lambda network: True, dict(page=1, size=2))
        self.assertEqual((everyone['total'], [row['username'] for row in everyone['rows']]),
                         (5, ['member', 'owner']))
        self.assertTrue(everyone['rows'][0]['held'] is not None)
        found = self.admin.member_list(self.organization, lambda network: True, dict(q='USER1@example'))
        self.assertEqual([row['username'] for row in found['rows']], ['user1'])
        other = self.other_network()
        lonely = self.account('lonely')
        self.organizations.join(lonely, self.organization, other)
        scoped = self.admin.member_list(self.organization, lambda network: str(network) == str(other), {})
        self.assertEqual([row['username'] for row in scoped['rows']], ['lonely'])

    # ---------- Through the panel ----------

    def logged(self, username, address):
        channel = self.open(username, address)
        return channel, self.login(channel)[1]

    def test_the_panel_lists_roles_and_what_the_viewer_may_do(self):
        self.role()
        channel, cookie = self.logged('owner', self.address)
        status, _, content = self.request(channel, 'GET', '/api/roles', cookie)
        self.assertEqual((status, content['can_add']), (200, True))
        self.assertEqual([(row['name'], row['actions']['modify']) for row in content['roles']],
                         [('Administrador', False), ('Soporte', True)])

    def test_role_names_alone_need_only_permissions_view(self):
        self.role()
        self.organizations.grant(self.owner, self.organization, self.member, {'permissions:view': 'all'})
        channel, cookie = self.logged('member', self.member_address)
        roles = self.request(channel, 'GET', '/api/roles', cookie)[2]['roles']
        self.assertEqual([('permissions' in row, row['actions']) for row in roles],
                         [(False, dict(modify=False, delete=False))] * 2)

    def test_roles_are_hidden_without_a_permission(self):
        channel, cookie = self.logged('member', self.member_address)
        self.assertEqual(self.request(channel, 'GET', '/api/roles', cookie)[0], 403)
        self.assertEqual(self.request(channel, 'GET', '/api/roles/members', cookie)[0], 403)

    def test_the_panel_creates_assigns_and_grants(self):
        channel, cookie = self.logged('owner', self.address)
        body = dict(name='Soporte', permissions={'members:view': 'all'})
        status, _, created = self.request(channel, 'POST', '/api/roles/create', cookie, body)
        self.assertEqual(status, 200)
        status, _, content = self.request(channel, 'POST', '/api/roles/create', cookie, body)
        self.assertEqual((status, content['code']), (400, 'role_name_taken'))

        members = self.request(channel, 'GET', '/api/roles/members?q=member', cookie)[2]
        row, = members['rows']
        self.assertEqual((row['me'], row['actions']['assign'], set(row['roles'])),
                         (False, True, {created['role_id'], str(self.administrator_role)}))
        body = dict(account_id=row['account_id'], role_id=created['role_id'])
        self.assertEqual(self.request(channel, 'POST', '/api/roles/assign', cookie, body)[0], 200)
        body = dict(account_id=row['account_id'], permissions={'rules:view': 'primary'})
        self.assertEqual(self.request(channel, 'POST', '/api/roles/permissions', cookie, body)[0], 200)
        self.assertEqual(self.member_of(self.member)['permissions'], {'rules:view': 'primary'})
        events = [event['kind'] for event in self.request(channel, 'GET', '/api/logs', cookie)[2]['events']]
        self.assertTrue({'role_created', 'role_assigned', 'permissions_changed'} <= set(events))

    def test_a_viewer_cannot_assign_a_role_it_does_not_cover(self):
        big = self.role('Grande', {'networks:delete': 'all'})
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'permissions:view': 'all', 'permissions:modify': 'all', 'members:view': 'all'})
        channel, cookie = self.logged('member', self.member_address)
        rows = self.request(channel, 'GET', '/api/roles/members', cookie)[2]['rows']
        owner, = [row for row in rows if row['username'] == 'owner']
        member, = [row for row in rows if row['username'] == 'member']
        self.assertEqual((owner['actions']['assign'], member['me']), (False, True))
        self.assertNotIn(str(big), member['roles'])
        self.assertNotIn(str(self.administrator_role), member['roles'])
        body = dict(account_id=str(self.member), role_id=str(big))
        self.assertEqual(self.request(channel, 'POST', '/api/roles/assign', cookie, body)[0], 403)


if __name__ == '__main__':
    unittest.main()
