import copy
import json
import unittest

from bson import ObjectId

from connection.admin import register_admin
from connection.network_admin import NetworkError
from connection.protocol import Protocol
from tests.panel import Panel


class BackupTest(Panel, unittest.TestCase):
    owner_address, member_address = ('127.0.0.1', 52000), ('127.0.0.1', 52001)

    def setUp(self):
        super().setUp()
        self.server.panel, self.notices = register_admin, []
        self.backups, self.networks = self.server.backup_admin, self.server.network_admin
        self.role = self.organizations.create_role(self.owner, self.organization, 'Soporte', {'status:view': 'all'})
        self.organizations.assign_role(self.owner, self.organization, self.member, self.role)
        self.member_ip = self.document(self.network_id)['connections'][str(self.member)]
        self.apply(self.server.access_admin.add_forward(self.owner, self.organization, self.network_id, dict(
            name='web', address='10.0.0.200', port=8080, protocol='tcp', target=self.member_ip, target_port=80)))
        self.apply(self.server.security_admin.add_rule(self.owner, self.organization, self.network_id, dict(
            action='block', source=dict(kind='account', id=str(self.member)), destination=dict(kind='any'),
            protocol='tcp', port=22)))
        self.apply(self.networks.set_limits(self.owner, self.organization, self.network_id,
                                            dict(roles={}, members={str(self.member): dict(down=500)})))

    def pump(self, server, cipher, address, stack):
        for packet in stack.transmit():
            server.send_packet((cipher.encrypt(packet), address))
        while server.server.packets:
            packet, destination = server.server.packets.pop(0)
            # Control notices are kept: a restore disconnects everyone.
            if destination != address or Protocol.packet_type(packet) == Protocol.control:
                self.notices.append(destination)
            else: stack.receive(cipher.decrypt(packet))

    def apply(self, effects):
        self.server.complete_change(dict(effects, organization_id=self.organization))
        return effects

    def document(self, network_id):
        return next(network for network in self.collections['networks'].documents if network['_id'] == network_id)

    def export(self):
        return json.loads(json.dumps(self.backups.export(self.owner, self.organization)))

    def restore(self, backup, confirm=True, actor=None):
        return self.backups.restore(actor or self.owner, self.organization, backup, confirm)

    def refused(self, backup, code='invalid_backup'):
        with self.assertRaises(NetworkError) as raised: self.restore(backup, confirm=False)
        self.assertEqual(raised.exception.code, code)

    @staticmethod
    def comparable(backup):
        return dict(backup, created=None)

    def test_the_copy_holds_the_configuration_and_no_secrets(self):
        backup = self.export()
        text = json.dumps(backup)
        self.assertNotIn('password', text)
        self.assertNotIn('$2b$', text)
        self.assertEqual((backup['format'], backup['version']), ('vpn-organization-backup', 1))
        network, = backup['networks']
        self.assertEqual(network['connections'][str(self.member)], self.member_ip)
        self.assertEqual(network['forwards'][0]['address'], '10.0.0.200')
        self.assertEqual(network['security']['rules'][0]['port'], 22)
        self.assertEqual(network['limits']['members'][str(self.member)]['down'], 500)
        self.assertEqual(sorted(role['name'] for role in backup['roles']), ['Administrador', 'Soporte'])
        member = next(member for member in backup['members'] if member['email'] == 'member@example.com')
        self.assertEqual((member['role_id'], member['networks'][str(self.network_id)]['mode']), (str(self.role), 'assigned'))

    def test_restoring_puts_everything_back_and_removes_the_rest(self):
        backup = self.export()
        # Changes after the copy: a new network, a new person, another role and no rules.
        created = self.apply(self.networks.create(self.owner, self.organization, '10.5.0.0/24', name='Nueva'))
        new_network = ObjectId(created['result']['network_id'])
        self.organizations.join(self.account('late'), self.organization, new_network)
        self.organizations.assign_role(self.owner, self.organization, self.member, None)
        rule = self.server.security_admin.security(self.organization, self.network_id)['rules'][0]['id']
        self.apply(self.server.security_admin.delete_rule(self.owner, self.organization, self.network_id, rule))
        preview = self.restore(backup, confirm=False)['result']
        self.assertEqual((preview['networks'], preview['members'], preview['leaving'], preview['skipped']), (1, 2, 1, []))
        self.assertEqual(len(self.collections['networks'].documents), 2)
        effects = self.apply(self.restore(backup))
        self.assertEqual(self.comparable(self.export()), self.comparable(backup))
        late = next(account['_id'] for account in self.collections['accounts'].documents if account['username'] == 'late')
        self.assertEqual(effects['kick'], [late])
        self.assertEqual(sorted(map(str, effects['disconnect'])), sorted([str(self.owner), str(self.member)]))
        self.assertIn(('remove', new_network), effects['panels'])
        self.assertNotIn(new_network, self.server.bridges)
        self.assertEqual(next(account for account in self.collections['accounts'].documents
                              if account['_id'] == late)['networks'], {})
        # The packet path follows: the rule and the forward are live again.
        self.assertEqual(len(self.server.firewall.networks[self.network_id]['rules']), 1)
        self.assertEqual(effects['event']['kind'], 'backup_restored')

    def test_a_copy_from_another_server_finds_people_by_email(self):
        backup = self.export()
        old = str(ObjectId())
        text = json.dumps(backup).replace(str(self.member), old)
        backup = json.loads(text)
        for member in backup['members']:
            if member['account_id'] == old: member['email'] = 'MEMBER@example.com'
        backup['members'].append(dict(account_id=str(ObjectId()), username='ghost', email='ghost@example.com',
                                      role_id=None, permissions={}, blocked=False,
                                      networks={str(self.network_id): dict(mode='assigned', primary=True)}))
        preview = self.restore(backup, confirm=False)['result']
        self.assertEqual(preview['skipped'], [dict(username='ghost', email='ghost@example.com')])
        self.apply(self.restore(backup))
        network = self.document(self.network_id)
        self.assertEqual(network['connections'][str(self.member)], self.member_ip)
        self.assertEqual(network['security']['rules'][0]['source']['id'], str(self.member))
        self.assertIn(str(self.member), network['limits']['members'])

    def test_routes_follow_the_source_address(self):
        created = self.apply(self.networks.create(self.owner, self.organization, '10.5.0.0/24'))
        other = created['result']['network_id']
        self.apply(self.server.access_admin.add_route(self.owner, self.organization, ObjectId(other),
                                                      'member@example.com', str(self.network_id)))
        backup = self.export()
        backup['networks'][1 if backup['networks'][1]['id'] == other else 0]['routes'] = {}
        self.apply(self.restore(backup))
        self.assertEqual(self.document(ObjectId(other))['routes'], {str(self.member): self.member_ip})

    def test_broken_copies_are_refused_whole(self):
        backup = self.export()
        network = str(self.network_id)
        administrator = next(role['id'] for role in backup['roles'] if role['administrator'])

        def changed(change):
            broken = copy.deepcopy(backup)
            change(broken)
            return broken

        cases = [
            lambda b: b.update(format='other'),
            lambda b: b.update(version=2),
            lambda b: b.update(networks=[]),
            lambda b: b.pop('members'),
            lambda b: b['networks'][0].update(network_range='nope'),
            lambda b: b['networks'][0].update(max_address=0),
            lambda b: b['networks'][0]['connections'].update({str(self.owner): '10.9.0.1'}),
            lambda b: b['networks'][0]['connections'].update({str(self.owner): self.member_ip}),
            lambda b: b['networks'][0]['forwards'][0].update(address=self.member_ip),
            lambda b: b['networks'][0]['forwards'][0].update(address='10.0.0.255'),
            lambda b: b['networks'][0]['forwards'][0].update(address='10.1.0.5'),
            lambda b: b['networks'][0]['forwards'][0].update(protocol='icmp'),
            lambda b: b['networks'][0]['security']['rules'][0].update(action='drop'),
            lambda b: b['networks'][0].update(limits=dict(members={'x': dict(down=-1)})),
            lambda b: b['networks'].append(dict(b['networks'][0], id=str(ObjectId()))),
            lambda b: b['roles'][0].update(permissions={'nothing:here': 'all'}),
            lambda b: [role.update(administrator=True) for role in b['roles']],
            lambda b: [role.update(administrator=False) for role in b['roles']],
            lambda b: b['roles'].append(dict(b['roles'][0], id=str(ObjectId()))),
            lambda b: b['members'][0].update(role_id=str(ObjectId())),
            lambda b: b['members'][0]['networks'][network].update(primary=False),
            lambda b: b['members'][0]['networks'][network].update(mode='routed', source=network),
            lambda b: b['members'][0].update(networks={str(ObjectId()): dict(mode='assigned', primary=True)}),
            lambda b: b['members'].append(dict(b['members'][0])),
            lambda b: b['members'][1].update(networks='x'),
        ]
        for case in cases:
            with self.subTest(case=cases.index(case)): self.refused(changed(case))
        # The person restoring must stay an administrator.
        mine = lambda b: next(member for member in b['members'] if member['account_id'] == str(self.owner))
        self.refused(changed(lambda b: mine(b).update(role_id=str(self.role))), 'backup_without_you')
        self.refused(changed(lambda b: b['members'].remove(mine(b))), 'backup_without_you')
        self.assertNotEqual(administrator, str(self.role))
        # Ids of another organization are not taken over.
        stranger = self.account('stranger')
        foreign = self.organizations.create(stranger)
        foreign_network = next(document['_id'] for document in self.collections['networks'].documents
                               if document.get('organization_id') == foreign)
        self.refused(json.loads(json.dumps(backup).replace(network, str(foreign_network))))
        # Nothing was written by any refusal.
        self.assertEqual(self.comparable(self.export()), self.comparable(backup))

    def test_only_an_administrator_restores(self):
        backup = self.export()
        with self.assertRaises(PermissionError): self.backups.export(self.member, self.organization)
        self.organizations.grant(self.owner, self.organization, self.member,
                                 {'organization:view': 'all', 'organization:modify': 'all'})
        self.assertEqual(self.backups.export(self.member, self.organization)['format'], 'vpn-organization-backup')
        with self.assertRaises(PermissionError): self.restore(backup, actor=self.member)

    def test_the_panel_downloads_and_restores(self):
        channel = self.open('owner', self.owner_address)
        _, cookie = self.login(channel)
        status, _, backup = self.request(channel, 'GET', '/api/backup', cookie)
        self.assertEqual((status, backup['format']), (200, 'vpn-organization-backup'))
        status, _, preview = self.request(channel, 'POST', '/api/backup/restore', cookie, dict(backup=backup))
        self.assertEqual((status, preview['confirm'], preview['members']), (200, True, 2))
        status, _, answer = self.request(channel, 'POST', '/api/backup/restore', cookie, dict(backup={'format': 'x'}))
        self.assertEqual((status, answer['code']), (400, 'invalid_backup'))
        status, _, done = self.request(channel, 'POST', '/api/backup/restore', cookie, dict(backup=backup, confirm=True))
        self.assertEqual((status, done['restored']), (200, True))
        # The answer left first; then the session was told to reconnect.
        self.assertIn(self.owner_address, self.notices)
        self.assertIn(self.network_id, self.server.bridges)


if __name__ == '__main__':
    unittest.main()
