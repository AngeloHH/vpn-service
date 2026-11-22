import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from bson import ObjectId

from connection.admin import api
from connection.admin.auth import WebSessions
from tests.panel import PANEL, Panel


def vpn_session(account_id=None, session_id=b'a' * 16, organization_id='org-a'):
    return SimpleNamespace(account_id=account_id or ObjectId(), organization_id=organization_id,
                           cipher=SimpleNamespace(session_id=session_id))


class WebSessionsTest(unittest.TestCase):
    def setUp(self):
        self.web, self.session = WebSessions(), vpn_session()

    def test_a_login_expires_after_15_idle_minutes(self):
        token = self.web.create(self.session, now=0)
        self.assertTrue(self.web.valid(token, self.session, now=899))
        self.assertTrue(self.web.valid(token, self.session, now=1798))
        self.assertFalse(self.web.valid(token, self.session, now=2699))

    def test_a_login_lasts_at_most_8_hours(self):
        token = self.web.create(self.session, now=0)
        for now in range(600, 28800, 600): self.web.valid(token, self.session, now=now)
        self.assertFalse(self.web.valid(token, self.session, now=28801))

    def test_a_login_survives_a_vpn_reconnection_in_its_organization(self):
        token = self.web.create(self.session, now=0)
        reconnected = vpn_session(self.session.account_id, b'b' * 16)
        self.assertTrue(self.web.valid(token, reconnected, now=1))
        elsewhere = vpn_session(self.session.account_id, b'c' * 16, organization_id='org-b')
        self.assertFalse(self.web.valid(token, elsewhere, now=2))
        self.assertFalse(self.web.valid(token, reconnected, now=3))

    def test_ending_an_account_drops_its_logins_in_one_organization(self):
        other = vpn_session(self.session.account_id, organization_id='org-b')
        here, there = self.web.create(self.session, now=0), self.web.create(other, now=0)
        stranger = self.web.create(vpn_session(), now=0)
        self.web.end(self.session.account_id, 'org-a')
        self.assertEqual(set(self.web.sessions), {there, stranger})
        self.web.end(self.session.account_id)
        self.assertEqual(set(self.web.sessions), {stranger})

    def test_the_wait_starts_at_the_third_failure_and_doubles(self):
        account_id = self.session.account_id
        waits = [self.web.failed(account_id, now=0) for _ in range(9)]
        self.assertEqual(waits, [0, 0, 60, 120, 240, 480, 960, 1920, 3600])
        self.assertEqual(self.web.blocked(account_id, now=3000), 600)

    def test_a_successful_login_resets_the_failures(self):
        for _ in range(3): self.web.failed(self.session.account_id, now=0)
        self.web.create(self.session, now=61)
        self.assertEqual(self.web.failed(self.session.account_id, now=62), 0)

    def test_cleanup_drops_expired_logins(self):
        token = self.web.create(self.session, now=0)
        self.web.cleanup(now=1000)
        self.assertNotIn(token, self.web.sessions)


class LoginTest(Panel, unittest.TestCase):
    address = '127.0.0.1', 50000

    def test_me_names_the_vpn_account_before_login(self):
        channel = self.open('owner', self.address)
        content = self.request(channel, 'GET', '/api/me')[2]
        self.assertEqual(content, dict(username='owner', email='owner@example.com',
                                       router=PANEL, logged_in=False, internet=False))

    def test_a_login_opens_the_panel(self):
        channel = self.open('owner', self.address)
        status, cookie = self.login(channel)
        self.assertEqual(status, 204)
        self.assertTrue(cookie.startswith('vpn_panel='))
        headers = self.request(channel, 'POST', '/api/logout', cookie)[1]
        self.assertIn('Max-Age=0', headers['set-cookie'])
        self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[0], 401)

    def test_the_cookie_is_http_only_and_strict(self):
        channel = self.open('owner', self.address)
        status, headers, _ = self.request(channel, 'POST', '/api/login',
                                          body=dict(password='password123*'))
        self.assertIn('HttpOnly', headers['set-cookie'])
        self.assertIn('SameSite=Strict', headers['set-cookie'])
        content = self.request(channel, 'GET', '/api/me',
                               headers['set-cookie'].split(';')[0])[2]
        self.assertTrue(content['logged_in'])
        self.assertTrue(content['administrator'])

    def test_the_password_is_checked_off_the_packet_loop(self):
        threads, check = [], api.srp.check

        def record(*arguments):
            threads.append(threading.current_thread())
            return check(*arguments)

        channel = self.open('owner', self.address)
        with mock.patch.object(api.srp, 'check', side_effect=record):
            self.assertEqual(self.login(channel)[0], 204)
        self.assertNotEqual(threads, [threading.main_thread()])
        self.assertEqual(len(threads), 1)

    def test_writes_need_the_panel_header(self):
        channel = self.open('owner', self.address)
        status = self.request(channel, 'POST', '/api/login', csrf=False,
                              body=dict(password='password123*'))[0]
        self.assertEqual(status, 403)

    def test_repeated_failures_block_the_account(self):
        channel = self.open('owner', self.address)
        results = [self.request(channel, 'POST', '/api/login', body=dict(password='wrong'))
                   for _ in range(3)]
        self.assertEqual([result[0] for result in results], [401, 401, 401])
        self.assertEqual(results[2][2]['retry_after'], 60)
        blocked = self.request(channel, 'POST', '/api/login', body=dict(password='password123*'))
        self.assertEqual(blocked[0], 429)
        self.assertGreater(blocked[2]['retry_after'], 50)

    def test_parallel_attempts_wait_for_the_one_in_progress(self):
        channel = self.open('owner', self.address)
        self.server.web_sessions.checking.add(self.owner)
        status = self.request(channel, 'POST', '/api/login', body=dict(password='password123*'))[0]
        self.assertEqual(status, 429)

    def test_a_session_replaced_during_the_check_gets_no_login(self):
        channel = self.open('owner', self.address)

        def replaced(*arguments):
            self.server.registry.remove_session(self.owner)
            return True

        body = b'{"password":"password123*"}'
        request = (f'POST /api/login HTTP/1.1\r\nHost: {PANEL}\r\nX-Requested-With: vpn-panel\r\n'
                   f'Content-Length: {len(body)}\r\n\r\n').encode() + body
        with mock.patch.object(api.srp, 'check', side_effect=replaced):
            channel[2].send(request)
            self.exchange(channel, lambda data: False)
        self.assertEqual(self.server.web_sessions.sessions, {})

    def test_a_vpn_reconnection_keeps_the_panel_login(self):
        channel = self.open('owner', self.address)
        cookie = self.login(channel)[1]
        # A new VPN login, as after a lost connection, still has the panel open.
        channel = self.open('owner', self.address)
        self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[0], 200)

    def test_a_kick_ends_the_panel_login(self):
        channel = self.open('owner', self.address)
        cookie = self.login(channel)[1]
        self.server.kick(self.owner)
        self.server.server.packets.clear()
        channel = self.open('owner', self.address)
        self.assertEqual(self.request(channel, 'GET', '/api/status', cookie)[0], 401)

    def test_the_login_belongs_to_the_session_account(self):
        owner = self.open('owner', self.address)
        cookie = self.login(owner)[1]
        member = self.open('member', ('127.0.0.1', 50001))
        self.assertEqual(self.request(member, 'GET', '/api/status', cookie)[0], 401)

    def test_logout_ends_the_status_events(self):
        channel = self.open('owner', self.address)
        cookie = self.login(channel)[1]
        token = cookie.split('=', 1)[1]
        request = f'GET /api/events HTTP/1.1\r\nHost: {PANEL}\r\nCookie: {cookie}\r\n\r\n'
        channel[2].send(request.encode())
        self.exchange(channel, lambda data: data.endswith(b'}\n\n\r\n'))
        self.server.web_sessions.remove(token)
        self.bridge.server.run_timers(time.monotonic() + 5)
        self.server.advance_bridges()
        self.assertIn(b'0\r\n\r\n', self.exchange(channel, lambda data: b'0\r\n\r\n' in data))


if __name__ == '__main__': unittest.main()
