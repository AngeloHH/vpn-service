import argparse
import hashlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import build


def dll(machine: int) -> bytes:
    # The smallest PE header the build reads.
    header = bytearray(512)
    header[:2] = b'MZ'
    struct.pack_into('<I', header, 0x3C, 0x80)
    header[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', header, 0x84, machine)
    return bytes(header)


class BuildTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.archive = self.folder / 'wintun.zip'
        with zipfile.ZipFile(self.archive, 'w') as opened:
            for name, machine in (('amd64', 0x8664), ('arm64', 0xAA64), ('x86', 0x14C)):
                opened.writestr(f'wintun/bin/{name}/wintun.dll', dll(machine))

    def options(self, **fields):
        values = dict(wintun=None, wintun_sha256=None, architecture='AMD64', system='Windows')
        return argparse.Namespace(**dict(values, **fields))

    def test_a_given_dll_is_used_where_it_is_without_internet(self):
        given = self.folder / 'mine' / 'wintun.dll'
        given.parent.mkdir()
        given.write_bytes(dll(0x8664))
        download = mock.Mock(side_effect=AssertionError('no internet'))
        verify = mock.Mock()
        found = build.wintun(self.options(wintun=str(given)), self.folder / 'work', download, verify)
        self.assertEqual(found, given)
        download.assert_not_called()
        verify.assert_not_called()

    def test_a_given_zip_gives_the_dll_of_this_architecture(self):
        for machine, code in (('AMD64', 0x8664), ('ARM64', 0xAA64), ('x86', 0x14C)):
            with self.subTest(machine=machine):
                found = build.wintun(self.options(wintun=str(self.archive), architecture=machine), self.folder / machine,
                                     mock.Mock(side_effect=AssertionError('no internet')))
                self.assertEqual(build.pe_machine(found), code)

    def test_a_dll_for_another_architecture_or_not_a_dll_stops_the_build(self):
        given = self.folder / 'wintun.dll'
        given.write_bytes(dll(0xAA64))
        with self.assertRaises(build.BuildError): build.wintun(self.options(wintun=str(given)), self.folder)
        given.write_bytes(b'not a dll')
        with self.assertRaises(build.BuildError): build.wintun(self.options(wintun=str(given)), self.folder)
        with self.assertRaises(build.BuildError):
            build.wintun(self.options(wintun=str(self.folder / 'missing.dll')), self.folder)

    def test_without_a_path_it_downloads_checks_and_verifies_the_signature(self):
        def download(url, target):
            self.assertEqual(url, build.WINTUN_URL)
            Path(target).write_bytes(self.archive.read_bytes())

        verify = mock.Mock(return_value='CN=WireGuard LLC')
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with mock.patch('builtins.print'):
            found = build.wintun(self.options(wintun_sha256=digest.upper()), self.folder / 'work', download, verify)
        verify.assert_called_once_with(found)
        with self.assertRaises(build.BuildError), mock.patch('builtins.print'):
            build.wintun(self.options(wintun_sha256='00' * 32), self.folder / 'work', download, verify)
        verify.side_effect = build.BuildError('no valid signature')
        with self.assertRaises(build.BuildError), mock.patch('builtins.print'):
            build.wintun(self.options(), self.folder / 'work', download, verify)
        with self.assertRaises(build.BuildError) as raised, mock.patch('builtins.print'):
            build.wintun(self.options(), self.folder / 'work', mock.Mock(side_effect=OSError('offline')), verify)
        self.assertIn('--wintun PATH', str(raised.exception))

    def test_one_executable_for_the_window_and_the_commands(self):
        given = self.folder / 'wintun.dll'
        arguments = build.command(self.options(), given)
        self.assertTrue(arguments[0].endswith(str(Path('connection') / '__main__.py')))
        self.assertEqual(arguments[arguments.index('--name') + 1], 'VPN')
        self.assertEqual(arguments[arguments.index('--add-binary') + 1], f'{given};.')
        # A console stays, so commands print and return exit codes; administrator rights are asked by the window.
        self.assertFalse({'--windowed', '--uac-admin'} & set(arguments))
        self.assertFalse({'--windowed', '--add-binary'} & set(build.command(self.options(system='Linux'))))
        self.assertIn('--windowed', build.command(self.options(system='Darwin')))

    def test_windows_gets_no_console_of_its_own_where_the_system_allows(self):
        arguments = build.command(self.options(), self.folder / 'wintun.dll')
        manifest = Path(arguments[arguments.index('--manifest') + 1])
        text = manifest.read_text(encoding='utf-8')
        self.assertIn('<consoleAllocationPolicy xmlns="http://schemas.microsoft.com/SMI/2024/WindowsSettings">'
                      'detached</consoleAllocationPolicy>', text)
        self.assertIn('level="asInvoker"', text)
        self.assertNotIn('--manifest', build.command(self.options(system='Linux')))
        try: from PyInstaller.utils.win32.winmanifest import create_application_manifest
        except ImportError: return
        # PyInstaller accepts it and keeps the policy when it writes the final manifest.
        self.assertIn(b'consoleAllocationPolicy', create_application_manifest(text.encode()))

    def test_other_systems_build_without_wintun(self):
        run = mock.Mock()
        with mock.patch('builtins.print') as shown:
            self.assertEqual(build.main(['--system', 'Linux', '--wintun', 'x.dll'], run=run), 0)
        shown.assert_called_once_with('Wintun is only for Windows: ignored.')
        self.assertNotIn('--add-binary', run.call_args.args[0])
        with mock.patch('builtins.print'):
            self.assertEqual(build.main(['--system', 'Windows', '--architecture', 'AMD64', '--wintun',
                                         str(self.folder / 'missing.dll')], run=run), 1)


if __name__ == '__main__': unittest.main()
