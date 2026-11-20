import json
import time

from bson import ObjectId
from tcp_sansio import TCPStack

from connection.admin import register_admin
from connection.organizations import Organizations
from connection.vpn_service import VPNServer
from tests import RECORD, login
from tests import test_vpn_service as tunnel
from tests.test_organizations import Collection

PANEL = '10.0.0.254'


class Panel:
    # A real VPN session talks to the panel through the encrypted tunnel.
    pump = tunnel.VPNServiceTest.pump
    control = tunnel.VPNServiceTest.control

    def setUp(self):
        names = 'accounts', 'networks', 'organizations', 'roles', 'members', 'connections', 'usage'
        self.collections = {name: Collection() for name in names}
        database = tunnel.Database(self.collections)
        self.organizations = Organizations(database)
        self.owner, self.member = self.account('owner'), self.account('member')
        self.organization = self.organizations.create(self.owner)
        self.network_id = self.collections['networks'].documents[0]['_id']
        self.organizations.join(self.member, self.organization, self.network_id)
        self.server = VPNServer(tunnel.MongoClient(database), 'database')
        self.server.server.close()
        self.server.server = tunnel.Socket()
        register_admin(self.server.add_virtual_http(self.network_id, PANEL), self.server)
        self.bridge = self.server.bridges[self.network_id]
        self.server.started = time.monotonic() - 100
        self.server.metrics = dict(cpu=1.5, memory=1024, memory_percent=0.5, temperature=None)
        self.seed = 0

    def tearDown(self):
        for socket in self.server.waker: socket.close()

    def account(self, username):
        account_id = ObjectId()
        self.collections['accounts'].documents.append(dict(
            _id=account_id, username=username, email=f'{username}@example.com',
            srp=RECORD, networks={}
        ))
        return account_id

    def vpn(self, username, address, network_id=None):
        cipher = login(self.server, address, username)
        reply = self.control(self.server, cipher, address, action='connect',
                             network_id=str(network_id or self.network_id))
        return cipher, reply['configuration'][0]['ip_address']

    def open(self, username, address):
        cipher, ip_address = self.vpn(username, address)
        self.seed += 1
        stack = TCPStack(ip_address, mtu=1420, seed=self.seed)
        connection = stack.connect(PANEL, 80)
        channel = cipher, stack, connection, address
        for _ in range(100):
            self.pump(self.server, cipher, address, stack)
            if connection.state == 'ESTABLISHED': break
        return channel

    def exchange(self, channel, until):
        # Deferred work finishes on a worker; the loop then sends its answer.
        cipher, stack, connection, address = channel
        received = bytearray()
        for _ in range(400):
            self.pump(self.server, cipher, address, stack)
            received.extend(connection.receive())
            if until(bytes(received)): break
            time.sleep(0.002)
            self.server.advance_bridges()
        return bytes(received)

    def request(self, channel, method, path, cookie=None, body=None,
                host=PANEL, csrf=True, close=False):
        lines = [f'{method} {path} HTTP/1.1', f'Host: {host}']
        if cookie: lines.append(f'Cookie: {cookie}')
        if csrf: lines.append('X-Requested-With: vpn-panel')
        if close: lines.append('Connection: close')
        content = json.dumps(body).encode() if body is not None else b''
        if body is not None:
            lines += ['Content-Type: application/json', f'Content-Length: {len(content)}']
        channel[2].send(('\r\n'.join(lines) + '\r\n\r\n').encode() + content)
        response = self.exchange(channel, complete)
        head, payload = response.split(b'\r\n\r\n', 1)
        status, headers = parse_head(head)
        return status, headers, json.loads(payload) if payload else None

    def login(self, channel, password='password123*'):
        status, headers, _ = self.request(channel, 'POST', '/api/login',
                                          body=dict(password=password))
        cookie = headers.get('set-cookie', '').split(';')[0]
        return status, cookie


def parse_head(head: bytes):
    lines = head.decode().split('\r\n')
    headers = dict(line.split(': ', 1) for line in lines[1:])
    return int(lines[0].split()[1]), {name.lower(): value for name, value in headers.items()}


def complete(response: bytes) -> bool:
    if b'\r\n\r\n' not in response: return False
    head, body = response.split(b'\r\n\r\n', 1)
    status, headers = parse_head(head)
    if status in (204, 304): return True
    return len(body) >= int(headers.get('content-length', -1))
