import os
import unittest

from cryptography.exceptions import InvalidTag

from connection import srp
from connection.errors import VPNError
from connection.protocol import ClientHandshake, PacketCipher, Protocol, ServerHandshake, Steps
from tests import PASSWORD, RECORD


class ProtocolTest(unittest.TestCase):
    def handshake(self, server=None):
        server = server or ServerHandshake()
        client = ClientHandshake()
        response, state = server.hello(client.hello())
        client.server_hello(response)
        return server, client, state

    def login(self, server, client, state, password=PASSWORD, record=RECORD):
        packet = client.login('ana', password)
        step, fields = server.request(packet, state)
        self.assertEqual((step, fields['username']), (Steps.login, 'ana'))
        proof = client.challenge(server.challenge(state, packet, 'ana', record, fields['public']))
        return server.finish(state, proof, server.request(proof, state)[1]['proof'])

    def test_registration_sends_a_verifier_and_never_the_password(self):
        server, client, state = self.handshake()
        packet = client.register('ana', 'ana@example.com', PASSWORD)
        for secret in (b'ana', b'example', PASSWORD.encode()): self.assertNotIn(secret, packet)
        step, fields = server.request(packet, state)
        self.assertEqual((step, fields['username'], fields['email']), (Steps.register, 'ana', 'ana@example.com'))
        self.assertTrue(srp.valid(fields['srp']))
        self.assertTrue(srp.check(PASSWORD, fields['srp']))
        client.registered(server.reply(state, Protocol.registered))
        with self.assertRaises(VPNError) as raised: client.registered(server.error_packet(state, 'username_taken'))
        self.assertEqual((raised.exception.code, str(raised.exception)), ('username_taken', 'The username is taken'))
        with self.assertRaises(VPNError) as raised:
            client.registered(server.error_packet(state, 'too_many_attempts', wait=7))
        self.assertEqual((raised.exception.details, str(raised.exception)), (dict(wait=7), 'Too many attempts: wait 7 seconds'))
        # Something that is not a code from the server is an invalid server.
        with self.assertRaises(VPNError) as raised: client.registered(server.reply(state, Protocol.error, b'not json'))
        self.assertEqual(raised.exception.code, 'invalid_server')

    def test_the_password_opens_matching_ciphers(self):
        server, client, state = self.handshake()
        keys = self.login(server, client, state)
        session_id = os.urandom(16)
        client_cipher = client.configuration(server.configuration(state, keys, session_id))
        server_cipher = PacketCipher(session_id, keys['server'], keys['client'])
        self.assertEqual(client_cipher.session_id, session_id)
        self.assertEqual(server_cipher.decrypt(client_cipher.encrypt(b'client packet')), b'client packet')
        self.assertEqual(client_cipher.decrypt(server_cipher.encrypt(b'server packet')), b'server packet')
        # Traffic keys differ from the ephemeral ones: the password is part of them.
        self.assertNotEqual(keys['client'], state['keys']['client'])

    def test_a_wrong_password_ends_in_an_error(self):
        server, client, state = self.handshake()
        self.assertIsNone(self.login(server, client, state, password='wrong'))
        with self.assertRaises(VPNError) as raised: client.configuration(server.error_packet(state))
        self.assertEqual(raised.exception.code, 'incorrect_credentials')

    def test_an_impostor_without_the_verifier_cannot_finish(self):
        server, client, state = self.handshake()
        # It answers with a record of its own: the client refuses its configuration.
        keys = self.login(server, client, state, record=srp.verifier('guess'))
        self.assertIsNone(keys)
        forged = server.configuration(state, dict(state['keys'], answer=b'\0' * 32), os.urandom(16))
        with self.assertRaises(ValueError): client.configuration(forged)

    def test_someone_relaying_in_the_middle_gets_no_usable_keys(self):
        # Two ephemeral exchanges: client with the relay, relay with the server.
        server = ServerHandshake()
        client, relay = ClientHandshake(), ClientHandshake()
        relay_server = ServerHandshake()
        to_client, client_state = relay_server.hello(client.hello())
        client.server_hello(to_client)
        to_relay, state = server.hello(relay.hello())
        relay.server_hello(to_relay)
        # The relay opens and re-encrypts every SRP message it passes on.
        def forward(packet):
            content = relay_server.decrypt(client_state['keys']['client_handshake'], packet)[2]
            return relay.request(content[0], content[1:])

        login = client.login('ana', PASSWORD)
        public_a = relay_server.request(login, client_state)[1]['public']
        forwarded = forward(login)
        challenge = server.challenge(state, forwarded, 'ana', RECORD, public_a)
        proof = client.challenge(relay_server.reply(client_state, Protocol.challenge,
                                                    relay.answer(challenge, Protocol.challenge)))
        forwarded = forward(proof)
        keys = server.finish(state, forwarded, server.request(forwarded, state)[1]['proof'])
        # The relayed proof is right, but the keys mix in both ephemeral exchanges:
        # the client cannot open what the server sends, and the relay cannot fix it.
        self.assertIsNotNone(keys)
        configuration = server.configuration(state, keys, os.urandom(16))
        relayed = configuration.replace(state['identifier'], client_state['identifier'], 1)
        with self.assertRaises(ValueError): client.configuration(relayed)
        self.assertEqual(client.srp.key, state['srp'].key)
        mine = ClientHandshake.keys(client.shared + client.srp.key, client.transcript)
        self.assertNotEqual(mine['server'], keys['server'])

    def test_unknown_names_receive_a_challenge_like_anyone(self):
        server, client, state = self.handshake()
        packet = client.login('ghost', PASSWORD)
        reply = server.challenge(state, packet, 'ghost', None, server.request(packet, state)[1]['public'])
        proof = client.challenge(reply)
        self.assertIsNone(server.finish(state, proof, server.request(proof, state)[1]['proof']))
        # The same name keeps the same salt: asking twice reveals nothing.
        again_server, again, again_state = self.handshake(server)
        packet = again.login('ghost', PASSWORD)
        again_server.challenge(again_state, packet, 'ghost', None, again_server.request(packet, again_state)[1]['public'])
        self.assertEqual(state['srp'].salt, again_state['srp'].salt)

    def test_broken_authentication_packets_are_refused(self):
        server, client, state = self.handshake()
        empty = client.encrypt(client.keys['client_handshake'], Protocol.authentication, client.identifier, b'')
        packets = [empty] + [client.request(step, content) for step, content in (
            (9, b''), (Steps.login, b'\x00\x05ab'), (Steps.proof, b'\x00\x01ab'), (Steps.register, b'\x00\x00'))]
        for packet in packets:
            with self.subTest(packet=packet), self.assertRaises(ValueError): server.request(packet, state)

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
