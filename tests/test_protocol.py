import importlib.util
import os
import pathlib
import unittest

from cryptography.exceptions import InvalidTag


file_path = pathlib.Path(__file__).parents[1] / 'connection' / 'protocol.py'
spec = importlib.util.spec_from_file_location('vpn_protocol', file_path)
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)

ClientHandshake = protocol.ClientHandshake
PacketCipher = protocol.PacketCipher
Protocol = protocol.Protocol
ServerHandshake = protocol.ServerHandshake


class ProtocolTest(unittest.TestCase):
    def handshake(self):
        server = ServerHandshake()
        client = ClientHandshake(server.public_key)
        hello = client.hello()
        response, state = server.hello(hello)
        client.server_hello(response)
        return server, client, state

    def test_handshake_encrypts_credentials(self):
        server, client, state = self.handshake()
        packet = client.credentials('username', 'password123*')
        self.assertNotIn(b'username', packet)
        self.assertNotIn(b'password123*', packet)
        self.assertEqual(
            server.credentials(packet, state),
            ('username', 'password123*')
        )

    def test_server_identity_must_match(self):
        server = ServerHandshake()
        client = ClientHandshake(ServerHandshake().public_key)
        response, _ = server.hello(client.hello())
        with self.assertRaises(ValueError): client.server_hello(response)

    def test_configuration_creates_directional_ciphers(self):
        server, client, state = self.handshake()
        session_id = os.urandom(16)
        packet = server.configuration(state, session_id)
        client_cipher = client.configuration(packet)
        server_cipher = PacketCipher(session_id, state['keys']['server'], state['keys']['client'])

        self.assertEqual(client_cipher.session_id, session_id)
        self.assertEqual(server_cipher.decrypt(client_cipher.encrypt(b'client packet')), b'client packet')
        self.assertEqual(client_cipher.decrypt(server_cipher.encrypt(b'server packet')), b'server packet')

    def test_packet_type_is_authenticated(self):
        server, client, state = self.handshake()
        session_id = os.urandom(16)
        client_cipher = PacketCipher(session_id, state['keys']['client'], state['keys']['server'], client=True)
        server_cipher = PacketCipher(session_id, state['keys']['server'], state['keys']['client'])
        packet = client_cipher.encrypt(b'{"request":1}', Protocol.control)

        with self.assertRaises(ValueError): server_cipher.decrypt(packet)
        forged = bytearray(packet)
        forged[5] = Protocol.data
        with self.assertRaises(InvalidTag): server_cipher.decrypt(bytes(forged))
        self.assertEqual(server_cipher.decrypt(packet, Protocol.control), b'{"request":1}')

    def test_packets_have_unique_counters_and_tags(self):
        server, client, state = self.handshake()
        session_id = os.urandom(16)
        client_cipher = PacketCipher(session_id, state['keys']['client'], state['keys']['server'], client=True)
        server_cipher = PacketCipher(session_id, state['keys']['server'], state['keys']['client'])
        first, second = client_cipher.encrypt(b'same packet'), client_cipher.encrypt(b'same packet')

        self.assertNotEqual(first, second)
        self.assertEqual(len(first), len(b'same packet') + 46)
        self.assertEqual(server_cipher.decrypt(second), b'same packet')
        self.assertEqual(server_cipher.decrypt(first), b'same packet')
        with self.assertRaises(ValueError): server_cipher.decrypt(first)

    def test_modified_packet_is_rejected(self):
        server, client, state = self.handshake()
        session_id = os.urandom(16)
        client_cipher = PacketCipher(session_id, state['keys']['client'], state['keys']['server'], client=True)
        server_cipher = PacketCipher(session_id, state['keys']['server'], state['keys']['client'])
        packet = bytearray(client_cipher.encrypt(b'protected packet'))
        packet[-1] ^= 1
        with self.assertRaises(InvalidTag): server_cipher.decrypt(bytes(packet))


if __name__ == '__main__': unittest.main()
