import mimetypes
import unittest
from pathlib import Path
from unittest import mock

from tcp_sansio import TCPStack

from connection.admin import WEB, register_admin
from connection.admin.static import content_type
from connection.virtual_http import VirtualHTTPServer
from tests import test_vpn_service as tunnel


def split_response(response: bytes):
    head, body = response.split(b'\r\n\r\n', 1)
    lines = head.decode().split('\r\n')
    headers = dict(line.split(': ', 1) for line in lines[1:])
    return lines[0], headers, body


class AdminStaticTest(unittest.TestCase):
    def get(self, path: str):
        http = register_admin(VirtualHTTPServer())
        request = f'GET {path} HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'
        return split_response(http.handle(request.encode()))

    def test_serves_the_index_at_the_root(self):
        status, headers, body = self.get('/')
        self.assertEqual(status, 'HTTP/1.1 200 OK')
        self.assertEqual(headers['Content-Type'], 'text/html; charset=utf-8')
        self.assertEqual(body, (WEB / 'index.html').read_bytes())

    def test_serves_every_referenced_asset_with_its_type(self):
        index = (WEB / 'index.html').read_text(encoding='utf-8')
        types = {'.css': 'text/css', '.js': 'text/javascript'}
        assets = ['/css/panel.css'] + [f'/js/{file.name}'
                                       for file in sorted((WEB / 'js').glob('*.js'))]
        for path in assets:
            self.assertIn(f'"{path}"', index)
            status, headers, body = self.get(path)
            self.assertEqual(status, 'HTTP/1.1 200 OK')
            content_type = types[path[path.rindex('.'):]] + '; charset=utf-8'
            self.assertEqual(headers['Content-Type'], content_type)
            self.assertEqual(body, (WEB / path[1:]).read_bytes())

    def test_types_ignore_the_global_registry(self):
        mimetypes.init()
        with mock.patch.dict(mimetypes.types_map, {'.js': 'text/plain'}):
            self.assertEqual(mimetypes.guess_type('app.js')[0], 'text/plain')
            self.assertEqual(content_type(Path('app.js')),
                             'text/javascript; charset=utf-8')
        self.assertEqual(content_type(Path('logo.png')), 'image/png')
        self.assertEqual(content_type(Path('data.xyz')), 'application/octet-stream')

    def test_files_outside_the_web_folder_are_not_served(self):
        for path in ('/static.py', '/../static.py', '/router-admin.html'):
            self.assertEqual(self.get(path)[0], 'HTTP/1.1 404 Not Found')


class AdminTunnelTest(unittest.TestCase):
    server = tunnel.VPNServiceTest.server
    login = tunnel.VPNServiceTest.login
    control = tunnel.VPNServiceTest.control
    authenticate = tunnel.VPNServiceTest.authenticate
    pump = tunnel.VPNServiceTest.pump

    def fetch(self, server, cipher, address, stack, path: str):
        connection = stack.connect('192.168.1.1', 80)
        for _ in range(100):
            self.pump(server, cipher, address, stack)
            if connection.state == 'ESTABLISHED': break
        request = f'GET {path} HTTP/1.1\r\nHost: 192.168.1.1\r\nConnection: close\r\n\r\n'
        connection.send(request.encode())
        response = bytearray()
        for _ in range(2000):
            self.pump(server, cipher, address, stack)
            response.extend(connection.receive())
            if connection.eof: break
        self.assertTrue(connection.eof)
        connection.close()
        for _ in range(20): self.pump(server, cipher, address, stack)
        return split_response(bytes(response))

    def test_admin_panel_crosses_the_encrypted_udp_tunnel(self):
        server, collections = self.server()
        network_id = collections['networks'].documents[0]['_id']
        register_admin(server.add_virtual_http(network_id, '192.168.1.1'))
        address = '127.0.0.1', 50000
        cipher = self.authenticate(server, address)
        operations = sum(collection.operations
                         for collection in collections.values())
        stack = TCPStack('192.168.1.2', mtu=1420, seed=1)

        for path, file in (('/', 'index.html'), ('/js/views.js', 'js/views.js')):
            status, headers, body = self.fetch(server, cipher, address, stack, path)
            self.assertEqual(status, 'HTTP/1.1 200 OK')
            self.assertEqual(body, (WEB / file).read_bytes())
        self.assertEqual(
            sum(collection.operations for collection in collections.values()),
            operations
        )


if __name__ == '__main__': unittest.main()
