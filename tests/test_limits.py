import unittest
from unittest import mock

from bson import ObjectId
from scapy.layers.inet import IP, UDP

from connection import limits as module
from connection.database.mongodb import Member, Network, Organization
from connection.limits import Limiter, TokenBucket, resolve, validate
from connection.usage import Usage, current_period
from tests.test_vpn_service import Collection
from connection.network_admin import NetworkError
from connection.protocol import Protocol
from tests.panel import Panel


class Clock:
    def __init__(self): self.now = 100.0

    def __call__(self): return self.now


class LimiterTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        patcher = mock.patch.object(module.time, 'monotonic', self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_bucket_allows_a_burst_then_its_rate(self):
        limiter = Limiter(network=(800, None))  # 100 000 bytes per second
        bucket = limiter.network['down']
        self.assertEqual((bucket.rate, bucket.capacity), (100_000, 50_000))
        self.assertTrue(limiter.allow('down', 50_000))
        self.assertFalse(limiter.allow('down', 1))
        self.clock.now += 0.25
        self.assertTrue(limiter.allow('down', 24_000))
        self.assertFalse(limiter.allow('down', 2_000))
        # Upload has no limit here.
        self.assertTrue(limiter.allow('up', 10 ** 9))

    def test_small_limits_still_let_a_whole_packet_through(self):
        self.assertEqual(TokenBucket(8).capacity, module.MINIMUM_BURST)

    def test_internet_traffic_needs_both_buckets_and_a_refusal_spends_nothing(self):
        limiter = Limiter(network=(None, 800), internet=(None, 400))
        self.assertTrue(limiter.allow('up', 32_768, internet=True))
        self.assertFalse(limiter.allow('up', 1, internet=True))
        # The network bucket kept what the refused packet did not take.
        self.assertTrue(limiter.allow('up', 50_000 - 32_768))
        self.assertEqual(limiter.limits(), dict(network=(None, 800), internet=(None, 400)))

    def test_changing_a_limit_replaces_only_that_bucket(self):
        limiter = Limiter(network=(800, 800))
        limiter.allow('down', 50_000), limiter.allow('up', 50_000)
        limiter.set(network=(800, 1600))
        self.assertFalse(limiter.allow('down', 1))
        self.assertTrue(limiter.allow('up', 100_000))
        limiter.set(network=(None, None))
        self.assertTrue(limiter.allow('down', 10 ** 9))

    def test_limits_are_validated(self):
        for invalid in ([], dict(roles=[]), dict(other={}), dict(roles={'x': dict(down='5')}),
                        dict(roles={'x': dict(down=0)}), dict(members={'x': dict(side=5)}),
                        dict(roles={'x': dict(down=module.MAXIMUM + 1)}), dict(roles={1: {}})):
            with self.assertRaises(ValueError): validate(invalid)
        empty = dict(down=None, up=None, quota_down=None, quota_up=None)
        self.assertEqual(validate(dict(roles={'r': {}}, members={'m': {}})), dict(roles={}, members={'m': empty}))
        with self.assertRaises(ValueError): validate(dict(roles={'x': dict(quota_down=module.MAXIMUM_QUOTA + 1)}))

    def test_a_person_overrides_its_role_direction_by_direction(self):
        limits = dict(roles={'role': dict(down=5000, up=1000)}, members={'person': dict(down=None, up=2000)})
        self.assertEqual(resolve(limits, 'role', 'person'), (None, 2000))
        self.assertEqual(resolve(limits, 'role', 'other'), (5000, 1000))
        self.assertEqual(resolve(limits, None, 'other'), (None, None))
        self.assertEqual(resolve(None, 'role', 'person'), (None, None))


class QuotaTest(unittest.TestCase):
    def setUp(self):
        self.collection, self.time = Collection(), [1_000_000.0]
        self.usage = Usage(lambda: self.collection, interval=5, clock=lambda: self.time[0])
        self.notices = []
        self.limiter = Limiter()
        self.keys = dict(network=('org', 'ana', 'net'), internet=('org', 'ana', 'internet'))
        self.limiter.bind(self.usage, self.keys, lambda scope, direction: self.notices.append((scope, direction)))

    def test_a_quota_cuts_once_the_month_is_spent(self):
        self.limiter.set_quotas(network=(1, None))  # 1 MB of download
        for _ in range(10): self.assertTrue(self.limiter.allow('down', 100_000))
        self.assertFalse(self.limiter.allow('down', 1))
        self.assertFalse(self.limiter.allow('down', 1))
        # Reported once; refused bytes are not counted; upload has no quota.
        self.assertEqual(self.notices, [('network', 'down')])
        self.assertEqual(self.usage.spent(self.keys['network']), [1_000_000, 0])
        self.assertTrue(self.limiter.allow('up', 5_000_000))

    def test_internet_traffic_spends_both_quotas(self):
        self.limiter.set_quotas(network=(None, None), internet=(None, 1))
        self.assertTrue(self.limiter.allow('up', 600_000, internet=True))
        self.assertFalse(self.limiter.allow('up', 600_000, internet=True))
        # The network still has room: traffic between members goes on.
        self.assertTrue(self.limiter.allow('up', 600_000))
        self.assertEqual(self.usage.spent(self.keys['network'])[1], 1_200_000)
        self.assertEqual(self.usage.spent(self.keys['internet'])[1], 600_000)
        self.assertEqual(self.notices, [('internet', 'up')])

    def test_consumption_is_written_and_restarts_each_month(self):
        self.collection.documents.append(dict(organization_id='org', account_id='ana', scope='net',
                                              period=self.usage.period, down=400, up=7))
        counter = self.usage.spent(self.keys['network'])
        self.assertEqual(counter, [400, 7])
        self.usage.add(self.keys['network'], 0, 100)
        self.usage.tick()
        self.assertTrue(self.usage.writes.empty())  # Not before the interval.
        self.usage.flush()
        stored = self.collection.find_one(dict(account_id='ana', scope='net'))
        self.assertEqual((stored['down'], stored['up']), (500, 7))
        self.usage.add(self.keys['internet'], 1, 30)
        self.usage.flush()
        self.assertEqual(self.collection.find_one(dict(scope='internet'))['up'], 30)

        self.usage.first_notice(self.keys['network'], 0)
        self.time[0] += 40 * 86400
        self.usage.tick()
        self.assertEqual(self.usage.period, current_period(self.time[0]))
        # The same counter, emptied: sessions holding it see the new month.
        self.assertIs(self.usage.spent(self.keys['network']), counter)
        self.assertEqual(counter, [0, 0])
        self.assertTrue(self.usage.first_notice(self.keys['network'], 0))


class ExtraTest(unittest.TestCase):
    def setUp(self):
        self.collection, self.time = Collection(), [1_000_000.0]
        self.usage = Usage(lambda: self.collection, clock=lambda: self.time[0])
        self.limiter = Limiter()
        self.keys = dict(network=('org', 'ana', 'net'), internet=('org', 'ana', 'internet'))
        self.extras = dict(network=[('org', 'account', 'ana', 'net'), ('org', 'role', 'guest', 'net')])
        self.limiter.bind(self.usage, self.keys, extras=self.extras)
        for key in self.extras['network']: self.usage.load_extra(key)

    def test_extras_add_to_the_quota_until_the_month_ends(self):
        self.limiter.set_quotas(network=(1, None))
        self.assertTrue(self.limiter.allow('down', 1_000_000))
        self.assertFalse(self.limiter.allow('down', 1))
        # Its own extra and its role's both count.
        self.usage.set_extra(('org', 'account', 'ana', 'net'), [500_000, 0])
        self.usage.set_extra(('org', 'role', 'guest', 'net'), [500_000, 0])
        self.assertTrue(self.limiter.allow('down', 1_000_000))
        self.assertFalse(self.limiter.allow('down', 1))
        self.time[0] += 40 * 86400
        self.usage.tick()
        self.assertEqual(self.usage.extra(('org', 'role', 'guest', 'net'), 0), 0)
        self.assertTrue(self.limiter.allow('down', 1_000_000))
        self.assertFalse(self.limiter.allow('down', 1))

    def test_extras_are_loaded_from_this_month_only(self):
        period = self.usage.period
        self.collection.documents += [dict(organization_id='org', role_id='staff', scope='net', period=period,
                                           extra_down=7, extra_up=9),
                                      dict(organization_id='org', role_id='staff', scope='net', period='2000-01',
                                           extra_down=100, extra_up=100)]
        self.assertEqual(self.usage.load_extra(('org', 'role', 'staff', 'net')), [7, 9])
        self.assertEqual(self.usage.extra(('org', 'role', 'nobody', 'net'), 1), 0)


class LimitsAdminTest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 55000), ('127.0.0.1', 55001)

    def setUp(self):
        super().setUp()
        self.admin = self.server.network_admin
        roles = self.organizations.roles
        self.administrator = roles.find_one(dict(organization_id=self.organization, administrator=True))['_id']
        self.guest = self.organizations.create_role(self.owner, self.organization, 'Invitado', {}, default=True)
        member = Member(self.collections['members']).get(organization_id=self.organization, account_id=self.member)
        Member(self.collections['members'], member['_id']).update(role_id=self.guest)

    def network_limits(self):
        return Network(self.collections['networks'], self.network_id).get().get('limits')

    def test_network_limits_are_stored_in_the_network(self):
        limits = dict(roles={str(self.guest): dict(down=5000, up=1000)}, members={})
        effects = self.admin.set_limits(self.owner, self.organization, self.network_id, limits)
        limits = validate(limits)
        self.assertEqual(self.network_limits(), limits)
        self.assertEqual(effects['limits'], ('network', self.network_id, limits))
        listed = self.admin.limits(self.organization, self.network_id)
        self.assertEqual([(row['name'], row['down'], row['up']) for row in listed['roles']],
                         [('Administrador', None, None), ('Invitado', 5000, 1000)])

    def test_internet_limits_are_stored_in_the_organization(self):
        limits = dict(roles={}, members={str(self.member): dict(down=None, up=500)})
        # Changing a network is not enough: these belong to the whole organization.
        self.organizations.grant(self.owner, self.organization, self.member, {'networks:modify': 'all'})
        with self.assertRaises(PermissionError):
            self.admin.set_limits(self.member, self.organization, None, limits)
        self.admin.set_limits(self.owner, self.organization, None, limits)
        organization = Organization(self.collections['organizations'], self.organization).get()
        self.assertEqual(organization['internet_limits'], validate(limits))
        rows = self.admin.limits(self.organization)['members']
        self.assertEqual([(row['username'], row['down'], row['up']) for row in rows], [('member', None, 500)])

    def test_nobody_limits_someone_with_more_access(self):
        self.organizations.grant(self.owner, self.organization, self.member, {'networks:modify': 'all'})
        own = dict(roles={str(self.guest): dict(down=100, up=None)}, members={})
        # The administrator role holds more than this member.
        with self.assertRaises(PermissionError):
            self.admin.set_limits(self.member, self.organization, self.network_id,
                                  dict(roles={str(self.administrator): dict(down=100, up=None)}))
        with self.assertRaises(PermissionError):
            self.admin.set_limits(self.member, self.organization, self.network_id,
                                  dict(members={str(self.owner): dict(down=100, up=None)}))
        self.admin.set_limits(self.owner, self.organization, self.network_id,
                              dict(roles={str(self.administrator): dict(down=900, up=None)}))
        # Entries it cannot change may stay as they are while it edits the rest.
        kept = dict(roles={str(self.administrator): dict(down=900, up=None), **own['roles']})
        self.admin.set_limits(self.member, self.organization, self.network_id, kept)
        self.assertEqual(self.network_limits()['roles'][str(self.guest)],
                         dict(down=100, up=None, quota_down=None, quota_up=None))

    def test_unknown_roles_and_people_are_refused(self):
        with self.assertRaises(NetworkError):
            self.admin.set_limits(self.owner, self.organization, self.network_id,
                                  dict(roles={str(ObjectId()): dict(down=1, up=None)}))
        with self.assertRaises(NetworkError):
            self.admin.set_limits(self.owner, self.organization, self.network_id,
                                  dict(members={str(ObjectId()): dict(down=1, up=None)}))
        with self.assertRaises(NetworkError):
            self.admin.set_limits(self.owner, self.organization, self.network_id, dict(roles={'x': 5}))

    def test_a_connection_takes_its_limits_and_follows_their_changes(self):
        self.admin.set_limits(self.owner, self.organization, self.network_id,
                              dict(roles={str(self.guest): dict(down=5000, up=1000)}))
        self.admin.set_limits(self.owner, self.organization, None,
                              dict(members={str(self.member): dict(down=300, up=None)}))
        self.vpn('member', self.member_address)
        self.vpn('owner', self.address)
        member = self.server.registry.get_account(self.member)
        owner = self.server.registry.get_account(self.owner)
        self.assertEqual(member.limiter.limits(), dict(network=(5000, 1000), internet=(300, None)))
        self.assertEqual(owner.limiter.limits(), dict(network=(None, None), internet=(None, None)))

        limits = dict(roles={str(self.guest): dict(down=None, up=8000)})
        self.server.refresh_limits(self.organization, 'network', self.network_id, validate(limits))
        self.assertEqual(member.limiter.limits()['network'], (None, 8000))
        internet = validate(dict(roles={str(self.guest): dict(quota_down=3)}))
        self.server.refresh_limits(self.organization, 'internet', None, internet)
        self.assertEqual(member.limiter.quotas['internet'], [3_000_000, None])
        # Another network's limits do not touch this connection.
        self.server.refresh_limits(self.organization, 'network', ObjectId(), validate(limits | dict(roles={})))
        self.assertEqual(member.limiter.limits()['network'], (None, 8000))


class LimitedTrafficTest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 56000), ('127.0.0.1', 56001)

    def test_traffic_between_members_is_limited_but_the_panel_is_not(self):
        member = Member(self.collections['members']).get(organization_id=self.organization, account_id=self.owner)
        Network(self.collections['networks'], self.network_id).update(
            limits=dict(roles={str(member['role_id']): dict(down=None, up=8)}, members={}))
        cipher, ip_address = self.vpn('owner', self.address)
        member_cipher, member_ip = self.vpn('member', self.member_address)
        self.server.server.packets.clear()
        packet = bytes(IP(src=ip_address, dst=member_ip) / UDP(sport=1, dport=2) / bytes(1000))
        for _ in range(100): self.server.send_packet((cipher.encrypt(packet), self.address))
        delivered = [item for item in self.server.server.packets
                     if item[1] == self.member_address and Protocol.packet_type(item[0]) == Protocol.data]
        # 32 KiB of burst at 1 kbps: about 31 packets of 1028 bytes, not 100.
        self.assertEqual(len(delivered), 31)
        self.server.server.packets.clear()
        # The panel still answers this heavily limited account.
        channel = self.open('owner', ('127.0.0.1', 56002))
        self.assertEqual(self.login(channel)[0], 204)


class LimitedDownloadTest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 56100), ('127.0.0.1', 56101)

    def test_what_a_member_receives_is_limited_too(self):
        Network(self.collections['networks'], self.network_id).update(
            limits=dict(roles={}, members={str(self.member): dict(down=8, up=None)}))
        cipher, ip_address = self.vpn('owner', self.address)
        member_ip = self.vpn('member', self.member_address)[1]
        self.server.server.packets.clear()
        packet = bytes(IP(src=ip_address, dst=member_ip) / UDP(sport=1, dport=2) / bytes(1000))
        for _ in range(100): self.server.send_packet((cipher.encrypt(packet), self.address))
        delivered = [item for item in self.server.server.packets if item[1] == self.member_address]
        self.assertEqual(len(delivered), 31)


class QuotaTrafficTest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 56200), ('127.0.0.1', 56201)

    def test_a_spent_quota_cuts_and_is_logged(self):
        # 1 MB of upload this month, 990 kB already spent before this connection.
        Network(self.collections['networks'], self.network_id).update(
            limits=dict(roles={}, members={str(self.owner): dict(down=None, up=None, quota_down=None, quota_up=1)}))
        self.collections['usage'].documents.append(dict(
            organization_id=str(self.organization), account_id=str(self.owner), scope=str(self.network_id),
            period=self.server.usage.period, down=0, up=990_000))
        cipher, ip_address = self.vpn('owner', self.address)
        member_ip = self.vpn('member', self.member_address)[1]
        self.server.server.packets.clear()
        reads = self.collections['usage'].operations
        packet = bytes(IP(src=ip_address, dst=member_ip) / UDP(sport=1, dport=2) / bytes(972))
        for _ in range(20): self.server.send_packet((cipher.encrypt(packet), self.address))
        # The consumption was loaded on connecting: no MongoDB access per packet.
        self.assertEqual(self.collections['usage'].operations, reads)
        delivered = [item for item in self.server.server.packets if item[1] == self.member_address]
        self.assertEqual(len(delivered), 10)
        events = [event for event in self.server.events.visible(self.organization, lambda _: True)
                  if event['kind'] == 'quota_reached']
        self.assertEqual([(event['username'], event['scope'], event['direction']) for event in events],
                         [('owner', 'network', 'up')])
        self.server.usage.flush()
        stored = self.collections['usage'].find_one(dict(account_id=str(self.owner), scope=str(self.network_id)))
        self.assertEqual(stored['up'], 1_000_000)

        # A bigger quota applies at once, without reconnecting.
        limits = validate(dict(members={str(self.owner): dict(quota_up=2)}))
        self.server.refresh_limits(self.organization, 'network', self.network_id, limits)
        self.assertTrue(self.server.registry.get_account(self.owner).limiter.allow('up', 1000))


class ExtraAdminTest(Panel, unittest.TestCase):
    address, member_address = ('127.0.0.1', 56300), ('127.0.0.1', 56301)

    def setUp(self):
        super().setUp()
        self.admin, self.period = self.server.network_admin, self.server.usage.period
        self.guest = self.organizations.create_role(self.owner, self.organization, 'Invitado', {}, default=True)
        member = Member(self.collections['members']).get(organization_id=self.organization, account_id=self.member)
        Member(self.collections['members'], member['_id']).update(role_id=self.guest)

    def grant(self, actor, network_id, kind, owner, down=0, up=0, clear=False):
        return self.admin.grant_extra(actor, self.organization, network_id, kind, owner, down, up, clear, self.period)

    def test_extras_are_stored_for_this_month_and_listed(self):
        effects = self.grant(self.owner, self.network_id, 'account', self.member, down=500)
        self.grant(self.owner, self.network_id, 'account', self.member, down=250, up=100)
        effects = self.grant(self.owner, None, 'role', self.guest, up=2000)
        self.assertEqual(effects['result'], dict(down=0, up=2000))
        self.assertEqual(effects['extra'], ((str(self.organization), 'role', str(self.guest), 'internet'), [0, 2_000_000_000]))
        stored = self.collections['usage'].find_one(dict(account_id=str(self.member), scope=str(self.network_id)))
        self.assertEqual((stored['extra_down'], stored['extra_up'], stored['period']), (750_000_000, 100_000_000, self.period))
        listed = self.admin.extras(self.organization, self.network_id, self.period)
        self.assertEqual([(row['kind'], row['name'], row['down'], row['up']) for row in listed],
                         [('account', 'member', 750, 100)])
        self.assertEqual([row['name'] for row in self.admin.extras(self.organization, None, self.period)], ['Invitado'])
        self.grant(self.owner, self.network_id, 'account', self.member, clear=True)
        self.assertEqual(self.admin.extras(self.organization, self.network_id, self.period), [])

    def test_extras_follow_the_rules_of_limits(self):
        for down, up in ((0, 0), (-1, 0), ('5', 0), (None, 0)):
            with self.assertRaises(NetworkError): self.grant(self.owner, self.network_id, 'account', self.member, down, up)
        with self.assertRaises(NetworkError): self.grant(self.owner, self.network_id, 'team', self.member, 5)
        with self.assertRaises(NetworkError): self.grant(self.owner, self.network_id, 'account', ObjectId(), 5)
        self.organizations.grant(self.owner, self.organization, self.member, {'networks:modify': 'all'})
        # A network is not enough for the internet, and nobody helps someone with more access.
        with self.assertRaises(PermissionError): self.grant(self.member, None, 'account', self.member, 5)
        with self.assertRaises(PermissionError): self.grant(self.member, self.network_id, 'account', self.owner, 5)
        administrator = self.organizations.roles.find_one(dict(administrator=True))['_id']
        with self.assertRaises(PermissionError): self.grant(self.member, self.network_id, 'role', administrator, 5)
        self.grant(self.member, self.network_id, 'role', self.guest, 5)

    def test_a_cut_member_gets_its_extra_at_once(self):
        Network(self.collections['networks'], self.network_id).update(
            limits=dict(roles={str(self.guest): dict(quota_up=1)}, members={}))
        channel = self.open('owner', self.address)
        cookie = self.login(channel)[1]
        self.vpn('member', self.member_address)
        session = self.server.registry.get_account(self.member)
        self.assertTrue(session.limiter.allow('up', 1_000_000))
        self.assertFalse(session.limiter.allow('up', 1))

        body = dict(network_id=str(self.network_id), kind='role', id=str(self.guest), up=1)
        status, _, content = self.request(channel, 'POST', '/api/limits/extra', cookie, body)
        self.assertEqual((status, content), (200, dict(down=0, up=1)))
        self.server.advance_bridges()
        self.assertTrue(session.limiter.allow('up', 1_000_000))
        self.assertFalse(session.limiter.allow('up', 1))
        listed = self.request(channel, 'GET', f'/api/limits?network={self.network_id}', cookie)[2]['extras']
        self.assertEqual([(row['name'], row['up']) for row in listed], [('Invitado', 1)])
        events = [event['kind'] for event in self.server.events.visible(self.organization, lambda _: True)]
        self.assertIn('extra_granted', events)

    def test_a_reconnection_keeps_this_months_extra(self):
        self.grant(self.owner, self.network_id, 'account', self.member, up=3)
        Network(self.collections['networks'], self.network_id).update(
            limits=dict(roles={str(self.guest): dict(quota_up=1)}, members={}))
        self.server.usage.extras.clear()  # As after a restart of the server.
        self.vpn('member', self.member_address)
        limiter = self.server.registry.get_account(self.member).limiter
        self.assertTrue(limiter.allow('up', 4_000_000))
        self.assertFalse(limiter.allow('up', 1))


class LimitsAPITest(Panel, unittest.TestCase):
    address = ('127.0.0.1', 57000)

    def test_limits_are_read_and_saved_from_the_panel(self):
        channel = self.open('owner', self.address)
        cookie = self.login(channel)[1]
        status, _, content = self.request(channel, 'GET', f'/api/limits?network={self.network_id}', cookie)
        self.assertEqual((status, content['can_edit'], len(content['roles'])), (200, True, 1))
        found = self.request(channel, 'GET', f'/api/limits/member?network={self.network_id}&email=MEMBER@example.com', cookie)
        self.assertEqual((found[0], found[2]['username']), (200, 'member'))
        self.assertEqual(self.request(channel, 'GET', f'/api/limits/member?email=nadie@example.com', cookie)[0], 404)

        body = dict(network_id=None, limits=dict(members={found[2]['account_id']: dict(down=1000, up=None)}))
        self.assertEqual(self.request(channel, 'POST', '/api/limits', cookie, body)[0], 200)
        internet = self.request(channel, 'GET', '/api/limits', cookie)[2]
        self.assertEqual([(row['username'], row['down']) for row in internet['members']], [('member', 1000)])
        body['limits'] = dict(roles={'x': 5})
        status, _, content = self.request(channel, 'POST', '/api/limits', cookie, body)
        self.assertEqual((status, content['code']), (400, 'invalid_limits'))
        events = [event['kind'] for event in self.request(channel, 'GET', '/api/logs', cookie)[2]['events']]
        self.assertIn('limits_changed', events)


if __name__ == '__main__':
    unittest.main()
