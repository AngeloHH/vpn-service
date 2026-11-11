import unittest
from collections import deque
from types import SimpleNamespace

from connection.vpn_service import VPNServer

from tests.panel import Panel


class TrafficTest(Panel, unittest.TestCase):
    address = '127.0.0.1', 50000

    def test_packets_are_counted_per_session_and_organization(self):
        channel = self.open('owner', self.address)
        self.request(channel, 'GET', '/api/me')
        session = self.server.registry.get_route(self.network_id, '10.0.0.1')
        received, sent = self.server.traffic[self.organization]

        self.assertGreater(received, 0)
        self.assertGreater(sent, 0)
        self.assertEqual((session.received, session.sent), (received, sent))

    def test_counters_become_kbps_once_per_second(self):
        self.server.traffic = {self.organization: [0, 0]}
        self.server.sample_traffic(now=10)
        self.server.traffic[self.organization] = [1250, 2500]
        self.server.sample_traffic(now=10.5)
        self.assertNotIn(self.organization, self.server.traffic_history)
        self.server.sample_traffic(now=11)
        # 2500 bytes sent in a second are 20 kbps of download for the users.
        self.assertEqual(list(self.server.traffic_history[self.organization]), [(20.0, 10.0)])

    def test_each_session_has_its_rates_and_packet_loss(self):
        replay = SimpleNamespace(counter=-1)
        session = SimpleNamespace(sent=0, received=0, packets=0, sampled=None, rates=(0.0, 0.0),
                                  loss=0.0, cipher=SimpleNamespace(replay=replay))
        VPNServer.sample_session(session, 1.0)
        self.assertEqual((session.rates, session.loss), ((0.0, 0.0), 0.0))

        # 20 packets were numbered by the client and 19 arrived: 5 % lost.
        session.sent, session.received, session.packets, replay.counter = 2500, 1250, 19, 19
        VPNServer.sample_session(session, 0.5)
        self.assertEqual((session.rates, session.loss), ((40.0, 20.0), 5.0))

        # An idle second keeps the last loss instead of reporting a false 0 %.
        VPNServer.sample_session(session, 1.0)
        self.assertEqual((session.rates, session.loss), ((0.0, 0.0), 5.0))

    def test_the_history_keeps_the_last_60_seconds(self):
        self.server.traffic = {self.organization: [0, 0]}
        for second in range(70):
            self.server.traffic[self.organization][1] += 125 * second
            self.server.sample_traffic(now=second)
        history = self.server.traffic_history[self.organization]
        self.assertEqual(len(history), 60)
        self.assertEqual(history[-1], (69.0, 0.0))

    def test_the_loop_wakes_for_the_next_sample(self):
        self.assertEqual(self.server.traffic_delay(now=5), 0)
        self.server.sample_traffic(now=5)
        self.assertAlmostEqual(self.server.traffic_delay(now=5.25), 0.75)

    def test_the_status_carries_only_its_organization_traffic(self):
        other = self.organizations.create(self.account('outsider'), network_range='10.9.0.0/24')
        self.server.traffic_history = {self.organization: deque([(8.0, 2.0)]),
                                       other: deque([(999.0, 999.0)])}
        traffic = self.server.status(self.organization)['traffic']
        self.assertEqual(traffic, dict(down=[8.0], up=[2.0]))


if __name__ == '__main__': unittest.main()
