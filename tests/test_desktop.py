import ast
import os
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

try:
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtCore import QSettings, QThreadPool
    from PySide6.QtWidgets import QApplication
except ImportError: QApplication = None

from connection.errors import MESSAGES, VPNError
from connection.organizations import Organizations
from connection.vpn_service import VPNClient
from tests import PASSWORD
from tests.test_register import PublicServer


@unittest.skipIf(QApplication is None, 'PySide6 is not installed')
class DesktopTest(PublicServer, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self):
        super().setUp()
        from connection.desktop.window import Window
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.settings = QSettings(str(Path(folder.name) / 'settings.ini'), QSettings.IniFormat)
        self.settings.setValue('language', 'es')
        self.window = Window(self.settings, client_class=lambda server: self.client())
        self.addCleanup(self.window.close)

    def wait(self):
        for _ in range(500):
            self.application.processEvents()
            QThreadPool.globalInstance().waitForDone(10)
            if not self.window.tasks: break
        self.application.processEvents()

    def fill(self, **fields):
        for name, value in fields.items(): getattr(self.window, f'field_{name}').setText(value)

    def register(self, username='ana', email='ana@example.com', password=PASSWORD, address=None):
        window = self.window
        window.show_page('register')
        self.fill(register_server='vpn.example', register_username=username, register_email=email,
                  register_password=password, register_repeat=password)
        window.register_button.click()
        self.wait()

    def login(self, password=PASSWORD):
        self.window.show_page('login')
        self.fill(login_server='vpn.example', login_username='ana', login_password=password)
        self.window.login_button.click()
        self.wait()

    def toast(self): return self.window.toast_text.text() if self.window.toast_box.isVisibleTo(self.window) else None

    def test_a_new_account_chooses_to_found_an_organization(self):
        window = self.window
        self.register()
        self.assertEqual(window.page, 'empty')
        self.assertIn('ana@example.com', window.waiting_text.text())
        # Passwords never stay in the fields or in the settings.
        self.assertEqual((window.field_register_password.text(), window.field_register_repeat.text()), ('', ''))
        self.assertNotIn(PASSWORD, repr({key: self.settings.value(key) for key in self.settings.allKeys()}))
        self.fill(organization='')
        window.found_button.click()
        self.wait()
        self.assertEqual((window.page, self.toast()), ('empty', 'El nombre necesita de 1 a 40 caracteres'))
        self.fill(organization='Taller')
        window.found_button.click()
        self.wait()
        self.assertEqual(window.page, 'home')
        self.assertEqual([network['organization'] for network in window.networks], ['Taller'])
        self.assertEqual(window.selected, window.networks[0]['network_id'])

    def test_waiting_until_an_administrator_adds_the_account(self):
        window = self.window
        self.register()
        window.check_button.click()
        self.wait()
        self.assertEqual((window.page, self.toast()), ('empty', 'Todavía sin redes.'))
        organizations = Organizations(self.database)
        owner = self.collections['accounts'].insert_one(dict(username='bea', email='bea@example.com', networks={}))
        other = organizations.create(owner.inserted_id, 'Oficina')
        organizations.join(self.accounts()[0]['_id'], other, self.collections['networks'].documents[0]['_id'])
        window.check_button.click()
        self.wait()
        self.assertEqual(window.page, 'home')
        self.assertEqual(window.networks[0]['organization'], 'Oficina')
        # With networks, the same page founds another organization or goes back.
        window.new_button.click()
        self.assertEqual((window.waiting_title.text(), window.check_button.text()), ('Nueva organización', 'Cancelar'))
        window.check_button.click()
        self.assertEqual(window.page, 'home')

    def test_errors_are_shown_by_code_in_the_chosen_language(self):
        self.register()
        self.login(password='wrong')
        self.assertEqual((self.window.page, self.toast()), ('login', 'Usuario o contraseña incorrectos'))
        self.window.language.setCurrentIndex(1)
        self.assertEqual(self.settings.value('language'), 'en')
        self.assertEqual(self.window.field_login_username.text(), 'ana')
        self.window.failed(VPNError('too_many_attempts', wait=9))
        self.assertEqual(self.toast(), 'Too many attempts: wait 9 seconds')
        self.window.show_page('register')
        self.fill(register_server='vpn.example', register_username='bea', register_email='bea@example.com',
                  register_password='one', register_repeat='two')
        self.window.register_button.click()
        self.assertEqual(self.toast(), 'The passwords do not match')
        self.fill(register_server='bad:port')
        self.window.register_button.click()
        self.assertEqual(self.toast(), 'Enter the server as host or host:port.')

    def test_connecting_disconnecting_and_failures(self):
        window = self.window
        self.register()
        self.fill(organization='Taller')
        window.found_button.click()
        self.wait()
        stopped, calls = threading.Event(), []

        def connect(client, credentials=None, interface='vpn0', network_id=None):
            calls.append((interface, network_id))
            client.networks = [dict(network_id=network_id, ip_address='10.0.0.1', primary=True,
                                    server=dict(ip_address='10.0.0.254', port=80))]
            stopped.wait(5)
            client.networks = []

        with mock.patch.object(VPNClient, 'connect', connect), \
                mock.patch.object(VPNClient, 'stop', lambda client: stopped.set()):
            window.connect_button.click()
            for _ in range(50):
                window.refresh_status()
                if window.state_tag.text() == 'Conectado': break
                threading.Event().wait(0.02)
            self.assertEqual(calls, [('vpn0', window.selected)])
            self.assertEqual((window.state_tag.text(), window.connect_button.text()), ('Conectado', 'Desconectar'))
            self.assertTrue(window.panel_button.isEnabled())
            # The tunnel owns the socket: no other request may start meanwhile.
            self.assertFalse(window.new_button.isEnabled())
            with mock.patch('connection.desktop.window.QDesktopServices.openUrl') as opened:
                window.panel_button.click()
            self.assertEqual(opened.call_args.args[0].toString(), 'http://10.0.0.254/')
            window.connect_button.click()
            window.tunnel.join(2)
            window.refresh_status()
            self.assertEqual((window.state_tag.text(), window.connect_button.text()), ('Desconectado', 'Conectar'))
        with mock.patch.object(VPNClient, 'connect', side_effect=VPNError('tunnel_failed', reason='Operation not permitted')):
            window.connect_button.click()
            window.tunnel.join(2)
            window.refresh_status()
        self.assertEqual(self.toast(), 'No se pudo crear la interfaz de red: Operation not permitted')

    def test_theme_and_logout(self):
        window = self.window
        theme = window.theme
        window.toggle_theme()
        self.assertNotEqual(window.theme, theme)
        self.assertEqual(self.settings.value('theme'), window.theme)
        self.register()
        window.logout()
        self.assertEqual((window.page, window.client), ('login', None))
        self.assertFalse(window.logout_button.isVisible())


class DesktopTextsTest(unittest.TestCase):
    def test_every_text_and_error_code_is_translated(self):
        from connection.desktop import texts
        source = (Path(__file__).parents[1] / 'connection' / 'desktop' / 'window.py').read_text(encoding='utf-8')
        keys = {match.group(1) + (match.group(2) or '') for match in
                re.finditer(r"(?:\bt|self\.texts)\(\s*'([^']+)'(?:\s*\n\s*'([^']+)')?", source)}
        tree = ast.parse(source)
        keys |= {node.value for node in ast.walk(tree) if isinstance(node, ast.Tuple)
                 for node in node.elts if isinstance(node, ast.Constant) and node.value in ('Red', 'Su IP', 'Bajada', 'Subida')}
        keys |= set(texts.ERRORS.values())
        self.assertEqual(set(texts.ERRORS), set(MESSAGES))
        for language, dictionary in texts.DICTIONARIES.items():
            with self.subTest(language=language): self.assertEqual(sorted(keys - set(dictionary)), [])

    def test_the_system_language_is_used_when_known(self):
        from connection.desktop.texts import Texts
        self.assertEqual([Texts(None, name).language for name in ('ru_RU', 'zh_CN', 'es_AR', 'de_DE', None)],
                         ['ru', 'zh', 'es', 'en', 'en'])
        self.assertEqual(Texts('zh').language, 'zh')


if __name__ == '__main__': unittest.main()
