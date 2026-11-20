import os
import unittest
from unittest import mock

from connection import __main__ as entry, console


class Kernel:
    def __init__(self, processes):
        self.processes, self.freed = processes, False

    def GetConsoleProcessList(self, buffer, size): return self.processes

    def GetConsoleWindow(self): return 7

    def FreeConsole(self): self.freed = True


class ConsoleTest(unittest.TestCase):
    def test_without_arguments_the_window_opens_and_with_them_the_commands_run(self):
        with mock.patch.object(entry, 'window', return_value=0) as window, \
                mock.patch.object(entry.client_cli, 'run', return_value=3) as run:
            self.assertEqual(entry.main([]), 0)
            window.assert_called_once_with()
            self.assertEqual(entry.main(['networks', 'vpn.example', 'ana']), 3)
            run.assert_called_once()
            window.assert_called_once_with()

    def test_the_window_asks_for_rights_once_and_hands_over_to_the_elevated_copy(self):
        with mock.patch.object(console, 'hide_own_console') as hide, \
                mock.patch.object(console, 'elevate', return_value=True), \
                mock.patch('connection.desktop.window.main') as desktop:
            self.assertEqual(entry.window(), 0)
        hide.assert_called_once_with()
        desktop.assert_not_called()
        with mock.patch.object(console, 'hide_own_console'), mock.patch.object(console, 'elevate', return_value=False), \
                mock.patch('connection.desktop.window.main', return_value=5) as desktop:
            self.assertEqual(entry.window(), 5)

    @unittest.skipIf(os.name == 'nt', 'checks the other systems')
    def test_other_systems_need_no_console_tricks(self):
        self.assertFalse(console.hide_own_console())
        self.assertFalse(console.elevate([]))

    def test_only_a_console_of_its_own_is_hidden_on_windows(self):
        user = mock.Mock()
        with mock.patch.object(console, 'windows', return_value=True):
            terminal = Kernel(processes=2)
            self.assertFalse(console.hide_own_console(terminal, user))
            self.assertFalse(terminal.freed)
            own = Kernel(processes=1)
            self.assertTrue(console.hide_own_console(own, user))
            self.assertTrue(own.freed)
            user.ShowWindow.assert_called_once_with(7, 0)

    def test_elevation_relaunches_with_the_same_arguments(self):
        shell = mock.Mock()
        shell.IsUserAnAdmin.return_value = 0
        shell.ShellExecuteW.return_value = 42
        with mock.patch.object(console, 'windows', return_value=True), \
                mock.patch.object(console.sys, 'frozen', True, create=True):
            self.assertTrue(console.elevate(['connect', 'a b'], shell))
        self.assertEqual(shell.ShellExecuteW.call_args.args[1:4], ('runas', console.sys.executable, 'connect "a b"'))
        # Declined in the Windows prompt: it goes on without rights.
        shell.ShellExecuteW.return_value = 5
        with mock.patch.object(console, 'windows', return_value=True):
            self.assertFalse(console.elevate([], shell))
        self.assertEqual(shell.ShellExecuteW.call_args.args[3], '-m connection')
        shell.IsUserAnAdmin.return_value = 1
        shell.ShellExecuteW.reset_mock()
        with mock.patch.object(console, 'windows', return_value=True):
            self.assertFalse(console.elevate([], shell))
        shell.ShellExecuteW.assert_not_called()


if __name__ == '__main__': unittest.main()
