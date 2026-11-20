import argparse
import io
import unittest
from unittest import mock

from connection import __main__ as entry, client_cli
from connection.client_cli import WAITING, Terminal
from connection.errors import VPNError
from connection.vpn_service import VPNClient
from tests import PASSWORD
from tests.test_register import PublicServer


class FakeTerminal(Terminal):
    def __init__(self, answers=(), secrets=(PASSWORD, PASSWORD), interactive=True):
        self.answers, self.secrets, self.shown, self.errors = list(answers), list(secrets), [], []
        super().__init__(ask=self.next_answer, secret=lambda prompt: self.secrets.pop(0),
                         show=self.shown.append, error=self.errors.append, interactive=interactive)

    def next_answer(self, prompt):
        self.shown.append(prompt)
        return self.answers.pop(0)


class ClientCLITest(PublicServer, unittest.TestCase):
    def parse(self, *arguments):
        parser = argparse.ArgumentParser()
        client_cli.add_commands(parser.add_subparsers(dest='command', required=True))
        return parser.parse_args(list(arguments))

    def run_cli(self, terminal, *arguments):
        return client_cli.run(self.parse(*arguments), terminal, client_class=lambda server: self.client())

    def test_registering_offers_to_found_an_organization(self):
        terminal = FakeTerminal(answers=['y', ' Taller '])
        self.assertEqual(self.run_cli(terminal, 'register', 'vpn.example', 'ana', 'ana@example.com'), 0)
        self.assertEqual(terminal.errors, [VPNError('no_networks').message])
        organization, = self.collections['organizations'].documents
        self.assertEqual(organization['name'], 'Taller')
        self.assertIn('Created the organization Taller; you administer it.', terminal.shown)

    def test_declining_waits_for_an_administrator(self):
        terminal = FakeTerminal(answers=['n'])
        code = self.run_cli(terminal, 'register', 'vpn.example', 'ana', 'ana@example.com')
        self.assertEqual(code, WAITING)
        self.assertEqual(self.collections['organizations'].documents, [])
        self.assertEqual(terminal.shown[-1], 'An administrator can add ana@example.com to an organization.')
        # Without a keyboard nothing is asked: the person waits too.
        self.assertEqual(self.run_cli(FakeTerminal(interactive=False), 'networks', 'vpn.example', 'ana'), WAITING)

    def test_scripts_found_it_with_a_flag_and_read_the_password_from_stdin(self):
        with mock.patch('sys.stdin', io.StringIO(PASSWORD + '\n')):
            code = self.run_cli(FakeTerminal(secrets=[], interactive=False), 'register', 'vpn.example', 'ana',
                                'ana@example.com', '--create-organization', 'Taller', '--password-stdin')
        self.assertEqual(code, 0)
        self.assertEqual(self.collections['organizations'].documents[0]['name'], 'Taller')
        terminal = FakeTerminal()
        self.assertEqual(self.run_cli(terminal, 'networks', 'vpn.example', 'ana'), 0)
        network = self.collections['networks'].documents[0]
        self.assertEqual(terminal.shown, [f"* {network['_id']}  10.0.0.0/24        10.0.0.1"])

    def test_refusals_show_their_code_and_end_with_an_error(self):
        self.register()
        terminal = FakeTerminal()
        self.assertEqual(self.run_cli(terminal, 'register', 'vpn.example', 'ANA', 'x@example.com'), 1)
        self.assertEqual(terminal.errors, ['Error: The username is taken (username_taken)'])
        terminal = FakeTerminal(secrets=['one', 'two'])
        self.assertEqual(self.run_cli(terminal, 'register', 'vpn.example', 'bea', 'bea@example.com'), 1)
        self.assertEqual(terminal.errors, ['Error: The passwords do not match (passwords_differ)'])
        terminal = FakeTerminal(secrets=['wrong'])
        self.assertEqual(self.run_cli(terminal, 'networks', 'vpn.example', 'ana'), 1)
        self.assertEqual(terminal.errors, ['Error: Incorrect credentials (incorrect_credentials)'])
        self.assertEqual(len(self.accounts()), 1)

    def test_founding_more_organizations(self):
        self.register()
        terminal = FakeTerminal()
        self.assertEqual(self.run_cli(terminal, 'organization', 'vpn.example', 'ana', 'Oficina'), 0)
        self.assertEqual(terminal.shown, ['Created the organization Oficina; you administer it.'])

    def test_connecting_needs_a_network_and_ends_cleanly(self):
        self.register()
        terminal = FakeTerminal(interactive=False)
        with mock.patch.object(VPNClient, 'connect') as connect:
            self.assertEqual(self.run_cli(terminal, 'connect', 'vpn.example', 'ana'), WAITING)
            connect.assert_not_called()
            terminal = FakeTerminal(answers=['y', 'Taller'])
            connect.side_effect = KeyboardInterrupt
            code = self.run_cli(terminal, 'connect', 'vpn.example', 'ana', '--interface', 'tun7', '--network', 'abc')
            self.assertEqual(code, 0)
            connect.assert_called_once_with(interface='tun7', network_id='abc')
            self.assertEqual(terminal.shown[-1], 'Disconnected.')
            # Being stopped by the system disconnects the same way; the handlers come back after.
            import signal
            before = signal.getsignal(signal.SIGTERM)
            connect.side_effect = lambda **fields: signal.raise_signal(signal.SIGTERM)
            terminal = FakeTerminal()
            self.assertEqual(self.run_cli(terminal, 'connect', 'vpn.example', 'ana'), 0)
            self.assertEqual(terminal.shown[-1], 'Disconnected.')
            self.assertEqual(signal.getsignal(signal.SIGTERM), before)
            connect.side_effect = VPNError('session_ended')
            terminal = FakeTerminal()
            self.assertEqual(self.run_cli(terminal, 'connect', 'vpn.example', 'ana'), 1)
            self.assertEqual(terminal.errors, ['Error: An administrator ended this session (session_ended)'])

    def test_server_addresses(self):
        self.assertEqual(client_cli.address('vpn.example'), ('vpn.example', 5732))
        self.assertEqual(client_cli.address('203.0.113.9:6000'), ('203.0.113.9', 6000))
        for text in ('vpn.example:port', 'vpn.example:70000', ':5732'):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError): client_cli.address(text)

    def test_the_entry_point_offers_the_client_commands(self):
        with mock.patch.object(client_cli, 'run', return_value=WAITING) as run:
            self.assertEqual(entry.main(['networks', 'vpn.example:6000', 'ana']), WAITING)
        options = run.call_args.args[0]
        self.assertEqual((options.server, options.username, options.handler), (('vpn.example', 6000), 'ana', client_cli.networks))

    def test_other_threads_switch_or_stop_the_tunnel_through_one_channel(self):
        client = VPNClient(('203.0.113.9', 5732))
        self.addCleanup(client.socket_server.close)
        chosen = []
        with mock.patch.object(VPNClient, 'select_network', side_effect=lambda network_id: chosen.append(network_id)):
            # Messages may arrive split or together; each line is one command.
            self.assertFalse(client.commanded(b'aaa'))
            self.assertFalse(client.commanded(b'bbb\nccc\n'))
            self.assertEqual(chosen, ['aaabbb', 'ccc'])
            self.assertTrue(client.commanded(b'ddd\nstop\n'))
        self.assertEqual(chosen, ['aaabbb', 'ccc', 'ddd'])
        with mock.patch.object(VPNClient, 'select_network', side_effect=VPNError('network_unavailable')):
            self.assertFalse(client.commanded(b'eee\n'))
        self.assertEqual(client.error.code, 'network_unavailable')
        client.speed_monitor.speed, client.speed_monitor.transferred = [5, 6], [7, 8]
        self.assertEqual(client.status(), dict(connected=False, network_id=None, networks=[], download=5, upload=6,
                                               received=7, sent=8))

    def test_a_tunnel_releases_its_routes_once(self):
        client = VPNClient(('203.0.113.9', 5732))
        self.addCleanup(client.socket_server.close)
        client.networks, client.interface = [dict(network_id='x')], 'tun7'
        with mock.patch('connection.vpn_service.remove_networks') as remove:
            client.release()
            client.release()
        remove.assert_called_once_with('tun7', [dict(network_id='x')], '203.0.113.9')


if __name__ == '__main__': unittest.main()
