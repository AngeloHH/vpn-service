import unittest

from bson import ObjectId

from connection.permissions import Permissions


class PermissionsTest(unittest.TestCase):
    def setUp(self):
        self.network_a, self.network_b = ObjectId(), ObjectId()

    def test_invalid_permissions_are_rejected(self):
        for value in ({'unknown:view': 'all'}, {'members:print': 'all'},
                      {'status:delete': 'all'}, {'members:view': 'some'},
                      {'roles:add': 'primary'}, {'members': 'all'},
                      {'organization:add': 'all'}, {'organization:modify': 'primary'},
                      {1: 'all'}, ['members:view']):
            with self.assertRaises(ValueError): Permissions.validate(value)

    def test_the_organization_can_be_modified_but_not_added(self):
        self.assertEqual(Permissions.validate({'organization:modify': 'all'}),
                         {'organization:modify': 'all'})

    def test_view_is_an_action_like_the_others(self):
        juan = Permissions({'members:add': 'all'})
        self.assertTrue(juan.allows('members:add'))
        self.assertFalse(juan.allows('members:view'))

    def test_the_primary_scope_is_where_the_change_happens(self):
        juan = Permissions({'members:modify': 'primary'}, primary=self.network_a)
        self.assertTrue(juan.allows('members:modify', self.network_a))
        self.assertFalse(juan.allows('members:modify', self.network_b))
        self.assertFalse(juan.allows('members:modify'))

    def test_role_and_direct_permissions_merge_with_the_broader_scope(self):
        role = {'members:modify': 'all', 'sessions:view': 'primary'}
        direct = {'members:modify': 'primary', 'sessions:delete': 'all'}
        juan = Permissions(role, direct, primary=self.network_a)
        self.assertEqual(juan.permissions, {'members:modify': 'all',
                                            'sessions:view': 'primary',
                                            'sessions:delete': 'all'})

    def test_the_administrator_is_allowed_everything(self):
        administrator = Permissions(administrator=True)
        self.assertTrue(administrator.allows('roles:delete'))
        self.assertTrue(administrator.covers({'networks:add': 'all'}))

    def test_a_grant_needs_every_permission(self):
        juan = Permissions({'members:view': 'all', 'members:add': 'all'})
        self.assertTrue(juan.covers({'members:view': 'all'}))
        self.assertFalse(juan.covers({'members:view': 'all', 'members:delete': 'all'}))

    def test_a_primary_grant_stays_inside_the_primary_network(self):
        juan = Permissions({'members:modify': 'primary'}, primary=self.network_a)
        primary = {'members:modify': 'primary'}
        self.assertTrue(juan.covers(primary, self.network_a))
        self.assertFalse(juan.covers(primary, self.network_b))
        self.assertFalse(juan.covers(primary))
        self.assertFalse(juan.covers({'members:modify': 'all'}, self.network_a))

    def test_all_covers_a_primary_grant_anywhere(self):
        juan = Permissions({'members:modify': 'all'}, primary=self.network_a)
        self.assertTrue(juan.covers({'members:modify': 'primary'}, self.network_b))

    def test_nobody_contains_a_member_with_more_access(self):
        juan = Permissions({'members:view': 'all', 'members:modify': 'all'})
        ana = Permissions({'members:view': 'all'})
        self.assertTrue(juan.contains(ana))
        self.assertFalse(ana.contains(juan))
        self.assertFalse(juan.contains(Permissions(administrator=True)))


if __name__ == '__main__': unittest.main()
