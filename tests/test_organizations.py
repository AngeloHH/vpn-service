import unittest

from bson import ObjectId

from connection.database.mongodb import Member, Network, Role
from connection.organizations import Organizations
from tests import test_vpn_service as tunnel


class Collection(tunnel.Collection):
    def find(self, query):
        self.operations += 1
        return [document for document in self.documents if tunnel.matches(document, query)]

    def delete_one(self, query):
        self.operations += 1
        document = self.find_one(query)
        if document: self.documents.remove(document)


class OrganizationsTest(unittest.TestCase):
    def setUp(self):
        names = 'accounts', 'networks', 'organizations', 'roles', 'members'
        self.database = tunnel.Database({name: Collection() for name in names})
        self.organizations = Organizations(self.database)
        self.owner = self.account()
        self.organization = self.organizations.create(self.owner)
        self.network_a = self.database['networks'].documents[0]['_id']
        network = Network(self.database['networks'])
        network.create('10.20.0.0/24', 253, self.organization)
        self.network_b = network.id

    def account(self):
        account_id = ObjectId()
        self.database['accounts'].documents.append(dict(_id=account_id, networks={}))
        return account_id

    def member(self, account_id):
        return Member(self.database['members']).get(organization_id=self.organization,
                                                    account_id=account_id)

    def joined(self, network_id):
        account_id = self.account()
        self.organizations.join(account_id, self.organization, network_id)
        return account_id

    def role(self, name, permissions, default=False):
        return self.organizations.create_role(self.owner, self.organization, name,
                                              permissions, default)

    def test_a_new_organization_starts_with_its_administrator(self):
        permissions = self.organizations.permissions(self.owner, self.organization)
        network = self.database['networks'].documents[0]
        roles = self.database['roles'].documents

        self.assertTrue(permissions.administrator)
        self.assertEqual([role['name'] for role in roles], ['Administrador'])
        self.assertEqual(network['organization_id'], self.organization)
        self.assertEqual(network['connections'][str(self.owner)], '10.0.0.1')
        self.assertEqual(permissions.primary, str(self.network_a))

    def test_new_members_receive_the_default_role(self):
        without_default = self.joined(self.network_a)
        guest = self.role('Invitado', {'members:view': 'all'}, default=True)
        member = self.joined(self.network_a)

        self.assertIsNone(self.member(without_default)['role_id'])
        self.assertEqual(self.member(member)['role_id'], guest)

    def test_only_one_role_is_the_default(self):
        first = self.role('Invitado', {'members:view': 'all'}, default=True)
        second = self.role('Soporte', {'sessions:view': 'all'}, default=True)
        defaults = [role['_id'] for role in self.database['roles'].documents
                    if role['default']]
        self.assertEqual(defaults, [second])
        self.assertNotEqual(first, second)

    def test_the_role_belongs_to_the_organization_not_the_network(self):
        self.role('Invitado', {'members:view': 'all'}, default=True)
        juan = self.joined(self.network_a)
        soporte = self.role('Soporte', {'sessions:view': 'all'})
        self.organizations.assign_role(self.owner, self.organization, juan, soporte)
        self.organizations.join(juan, self.organization, self.network_b)

        self.assertEqual(self.member(juan)['role_id'], soporte)
        self.assertEqual(self.organizations.primary_network(juan, self.organization),
                         str(self.network_a))

    def test_a_network_of_another_organization_is_rejected(self):
        other = self.organizations.create(self.account())
        other_network = Network(self.database['networks']).get(organization_id=other)
        with self.assertRaises(ValueError):
            self.organizations.join(self.account(), self.organization, other_network['_id'])

    def test_juan_manages_members_only_in_his_primary_network(self):
        juan = self.joined(self.network_a)
        editor = self.role('Editor', {'members:modify': 'primary'})
        self.organizations.assign_role(self.owner, self.organization, juan, editor)
        permissions = self.organizations.permissions(juan, self.organization)

        self.assertTrue(permissions.allows('members:modify', self.network_a))
        self.assertFalse(permissions.allows('members:modify', self.network_b))

    def test_a_grant_cannot_exceed_the_granter(self):
        juan, ana, bob = (self.joined(self.network_a), self.joined(self.network_a),
                          self.joined(self.network_b))
        self.organizations.grant(self.owner, self.organization, juan,
                                 {'permissions:add': 'all', 'members:modify': 'primary'})
        primary = {'members:modify': 'primary'}

        self.organizations.grant(juan, self.organization, ana, primary)
        with self.assertRaises(PermissionError):
            self.organizations.grant(juan, self.organization, bob, primary)
        with self.assertRaises(PermissionError):
            self.organizations.grant(juan, self.organization, ana, {'members:modify': 'all'})
        self.assertEqual(self.member(ana)['permissions'], primary)

    def test_a_role_needs_permissions_the_creator_holds(self):
        juan = self.joined(self.network_a)
        self.organizations.grant(self.owner, self.organization, juan,
                                 {'roles:add': 'all', 'members:view': 'all'})

        self.organizations.create_role(juan, self.organization, 'Lector',
                                       {'members:view': 'all'})
        with self.assertRaises(PermissionError):
            self.organizations.create_role(juan, self.organization, 'Editor',
                                           {'members:modify': 'all'})
        with self.assertRaises(PermissionError):
            self.organizations.create_role(self.joined(self.network_a), self.organization,
                                           'Lector', {})

    def test_revoking_removes_only_the_named_permissions(self):
        juan = self.joined(self.network_a)
        self.organizations.grant(self.owner, self.organization, juan,
                                 {'members:view': 'all', 'sessions:view': 'primary'})
        self.organizations.revoke(self.owner, self.organization, juan, ['members:view'])
        self.assertEqual(self.member(juan)['permissions'], {'sessions:view': 'primary'})

    def test_nobody_changes_a_member_with_more_access(self):
        juan = self.joined(self.network_a)
        self.organizations.grant(self.owner, self.organization, juan, {
            'permissions:add': 'all', 'permissions:delete': 'all', 'permissions:modify': 'all'
        })
        with self.assertRaises(PermissionError):
            self.organizations.revoke(juan, self.organization, self.owner, ['members:view'])
        administrator = Role(self.database['roles']).get(administrator=True)['_id']
        with self.assertRaises(PermissionError):
            self.organizations.assign_role(juan, self.organization, juan, administrator)

    def test_the_last_administrator_cannot_be_removed(self):
        with self.assertRaises(ValueError):
            self.organizations.assign_role(self.owner, self.organization, self.owner, None)
        administrator = Role(self.database['roles']).get(administrator=True)['_id']
        second = self.joined(self.network_a)
        self.organizations.assign_role(self.owner, self.organization, second, administrator)
        self.organizations.assign_role(self.owner, self.organization, self.owner, None)
        self.assertFalse(self.organizations.permissions(self.owner, self.organization).administrator)

    def test_members_of_a_deleted_role_fall_back_to_the_default(self):
        guest = self.role('Invitado', {'members:view': 'all'}, default=True)
        soporte = self.role('Soporte', {'sessions:view': 'all'})
        juan = self.joined(self.network_a)
        self.organizations.assign_role(self.owner, self.organization, juan, soporte)
        self.organizations.delete_role(self.owner, self.organization, soporte)

        self.assertEqual(self.member(juan)['role_id'], guest)
        administrator = Role(self.database['roles']).get(administrator=True)['_id']
        with self.assertRaises(PermissionError):
            self.organizations.delete_role(self.owner, self.organization, administrator)


if __name__ == '__main__': unittest.main()
