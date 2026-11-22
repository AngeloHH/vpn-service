import json
import os
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from connection import errors, srp


class Protocol:
    magic, version = b'SVPN', 2
    client_hello, server_hello = 1, 2
    authentication, configuration = 3, 4
    data, error, control = 5, 6, 7
    challenge, registered = 8, 9
    header = struct.Struct('!4sBB16s')

    @classmethod
    def pack(cls, packet_type: int, identifier: bytes, packet: bytes = b'') -> bytes:
        error = 'The packet identifier must contain 16 bytes'
        if len(identifier) != 16: raise ValueError(error)
        return cls.header.pack(cls.magic, cls.version, packet_type, identifier) + packet

    @classmethod
    def unpack(cls, packet: bytes, packet_type: int = None) -> tuple:
        error = 'The protocol packet is incomplete'
        if len(packet) < cls.header.size: raise ValueError(error)
        # Separate the authenticated header from its variable payload.
        packet_header = packet[:cls.header.size]
        packet = packet[cls.header.size:]
        arguments = cls.header.unpack(packet_header)
        magic, version, current_type, identifier = arguments
        error = 'Unknown protocol packet'
        invalid_version = magic != cls.magic or version != cls.version
        if invalid_version: raise ValueError(error)
        error = 'Unexpected protocol packet'
        unexpected = packet_type is not None and current_type != packet_type
        if unexpected: raise ValueError(error)
        return current_type, identifier, packet, packet_header

    @classmethod
    def packet_type(cls, packet: bytes) -> int:
        return cls.unpack(packet)[0]


class ReplayWindow:
    def __init__(self, length: int = 64):
        self.length, self.counter, self.window = length, -1, 0

    def can_receive(self, counter: int) -> bool:
        difference = self.counter - counter
        if counter > self.counter: return True
        was_received = (self.window >> difference) & 1
        return difference < self.length and not was_received

    def update(self, counter: int):
        if counter > self.counter:
            difference = counter - self.counter
            window = (self.window << difference) | 1
            self.counter = counter
            self.window = window & ((1 << self.length) - 1)
            return
        self.window |= 1 << (self.counter - counter)


class PacketCipher:
    def __init__(self, session_id: bytes, send_key: bytes,
                 recv_key: bytes, client: bool = False):
        self.session_id, self.counter = session_id, 0
        self.keys = send_key, recv_key, client
        # Separate ciphers and nonce domains prevent direction collisions.
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.replay = ReplayWindow()
        self.recv_cipher = ChaCha20Poly1305(recv_key)
        self.send_direction = bytes([0, 0, 0, 1 if client else 2])
        self.recv_direction = bytes([0, 0, 0, 2 if client else 1])

    def state(self) -> dict:
        # Everything another process needs to continue this session without reusing a nonce.
        send_key, recv_key, client = self.keys
        return dict(send_key=send_key, recv_key=recv_key, client=client, counter=self.counter,
                    replay=(self.replay.counter, self.replay.window))

    @classmethod
    def restored(cls, session_id: bytes, state: dict) -> 'PacketCipher':
        cipher = cls(session_id, state['send_key'], state['recv_key'], state['client'])
        cipher.counter = state['counter']
        cipher.replay.counter, cipher.replay.window = state['replay']
        return cipher

    def encrypt(self, packet: bytes, packet_type: int = Protocol.data, session_id: bytes = None) -> bytes:
        # A direction prefix and monotonic counter form the unique nonce.
        counter = self.counter.to_bytes(8, 'big')
        self.counter += 1
        nonce = self.send_direction + counter
        # The complete header is authenticated with the encrypted payload.
        header = Protocol.pack(packet_type, session_id or self.session_id, counter)
        encrypted = self.send_cipher.encrypt(nonce, packet, header)
        return header + encrypted

    def decrypt(self, packet: bytes, packet_type: int = Protocol.data, session_id: bytes = None) -> bytes:
        # Read the public routing fields before authenticating the payload.
        # session_id: a previous identifier, while a moved session's client still uses it.
        details = Protocol.unpack(packet, packet_type)
        identifier, encrypted, header = details[1:]
        error = 'Invalid encrypted packet'
        invalid = identifier != (session_id or self.session_id) or len(encrypted) < 24
        if invalid: raise ValueError(error)
        # Verify the packet before advancing the anti-replay window.
        counter, encrypted = encrypted[:8], encrypted[8:]
        number = int.from_bytes(counter, 'big')
        error = 'Repeated encrypted packet'
        repeated = not self.replay.can_receive(number)
        if repeated: raise ValueError(error)
        nonce = self.recv_direction + counter
        packet = self.recv_cipher.decrypt(nonce, encrypted, header + counter)
        self.replay.update(number)
        return packet


class Handshake:
    context = b'simple-vpn handshake version 2'

    @staticmethod
    def public_bytes(key) -> bytes:
        encoding = serialization.Encoding.Raw
        key_format = serialization.PublicFormat.Raw
        return key.public_bytes(encoding, key_format)

    @staticmethod
    def private_bytes(key) -> bytes:
        encoding = serialization.Encoding.Raw
        encryption = serialization.NoEncryption()
        key_format = serialization.PrivateFormat.Raw
        return key.private_bytes(encoding, key_format, encryption)

    @classmethod
    def keys(cls, shared_key: bytes, transcript: bytes) -> dict:
        # Bind every derived key to the complete transcript.
        algorithm = hashes.SHA256()
        digest = hashes.Hash(algorithm)
        digest.update(transcript)
        digest = digest.finalize()
        # Derive independent handshake and traffic keys per direction.
        kwargs = dict(algorithm=algorithm, length=128)
        kwargs.update(salt=digest, info=cls.context)
        material = HKDF(**kwargs).derive(shared_key)
        keys = dict(client_handshake=material[:32], client=material[64:96])
        keys.update(server_handshake=material[32:64], server=material[96:])
        return keys

    @staticmethod
    def encrypt(key: bytes, packet_type: int,
                identifier: bytes, content: bytes) -> bytes:
        nonce = os.urandom(12)
        packet = Protocol.pack(packet_type, identifier)
        content = ChaCha20Poly1305(key).encrypt(nonce, content, packet)
        return packet + nonce + content

    @staticmethod
    def decrypt(key: bytes, packet: bytes, packet_type: int = None) -> tuple:
        details = Protocol.unpack(packet, packet_type)
        current_type, identifier, content, header = details
        error = 'The encrypted handshake packet is incomplete'
        invalid = len(content) < 28
        if invalid: raise ValueError(error)
        content = ChaCha20Poly1305(key).decrypt(content[:12], content[12:], header)
        return current_type, identifier, content


def pack_fields(*fields: bytes) -> bytes:
    # Each field carries its own length so none can bleed into the next.
    return b''.join(struct.pack('!H', len(field)) + field for field in fields)


def unpack_fields(content: bytes, count: int) -> list[bytes]:
    fields = []
    for _ in range(count):
        if len(content) < 2: raise ValueError('Invalid authentication packet')
        length, content = struct.unpack('!H', content[:2])[0], content[2:]
        if len(content) < length: raise ValueError('Invalid authentication packet')
        fields.append(content[:length])
        content = content[length:]
    if content: raise ValueError('Invalid authentication packet')
    return fields


class Steps:
    # The first byte of an authentication packet says what the client asks.
    register, login, proof = 1, 2, 3


class ServerHandshake(Handshake):
    """The server side: an ephemeral exchange, then the password (SRP) decides.

    There is no identity a client has to know beforehand. The ephemeral
    exchange hides what travels; SRP proves both sides and its key is mixed
    into the traffic keys, so someone in the middle can neither read nor finish.
    """

    def __init__(self, secret: bytes or str = None):
        if type(secret) is str: secret = bytes.fromhex(secret)
        # Only invents stable answers for unknown names; never leaves the server.
        self.secret = secret or os.urandom(32)

    def hello(self, packet: bytes) -> tuple:
        details = Protocol.unpack(packet, Protocol.client_hello)
        identifier, content = details[1:3]
        if len(content) != 32: raise ValueError('The client public key is invalid')
        client_key = X25519PublicKey.from_public_bytes(content)
        private_key = X25519PrivateKey.generate()
        reply = Protocol.pack(Protocol.server_hello, identifier, self.public_bytes(private_key.public_key()))
        shared_key = private_key.exchange(client_key)
        state = dict(identifier=identifier, created=time.monotonic(), shared=shared_key,
                     keys=self.keys(shared_key, packet + reply), reply=reply, transcript=packet + reply)
        return reply, state

    def request(self, packet: bytes, state: dict) -> tuple:
        # What the client asks, read inside the ephemeral channel.
        details = self.decrypt(state['keys']['client_handshake'], packet, Protocol.authentication)
        _, identifier, content = details
        if identifier != state['identifier'] or not content: raise ValueError('Invalid authentication packet')
        step, content = content[0], content[1:]
        if step == Steps.register:
            username, email, salt, verifier, iterations = unpack_fields(content, 5)
            if len(iterations) != 4: raise ValueError('Invalid authentication packet')
            return step, dict(username=username.decode(), email=email.decode(), srp=dict(
                salt=salt.hex(), verifier=verifier.hex(), iterations=struct.unpack('!I', iterations)[0]))
        if step == Steps.login:
            username, public_a = unpack_fields(content, 2)
            return step, dict(username=username.decode(), public=public_a)
        if step == Steps.proof:
            return step, dict(proof=unpack_fields(content, 1)[0])
        raise ValueError('Invalid authentication packet')

    def reply(self, state: dict, packet_type: int, content: bytes = b'') -> bytes:
        return self.encrypt(state['keys']['server_handshake'], packet_type, state['identifier'], content)

    def challenge(self, state: dict, packet: bytes, username: str, record: dict, public_a: bytes) -> bytes:
        # Unknown names receive an invented record and simply fail at the proof.
        record = record if srp.valid(record) else srp.fake(self.secret, username)
        salt = bytes.fromhex(record['salt'])
        state['srp'] = srp.Server(username, salt, bytes.fromhex(record['verifier']), public_a)
        content = pack_fields(salt, srp.GROUP.pad(state['srp'].public), struct.pack('!I', record['iterations']))
        reply = self.reply(state, Protocol.challenge, content)
        state['transcript'] += packet + reply
        return reply

    def finish(self, state: dict, packet: bytes, proof: bytes) -> dict or None:
        # A wrong password ends here; a right one yields keys bound to everything seen.
        answer = state['srp'].verify(proof)
        if answer is None: return None
        state['transcript'] += packet
        keys = self.keys(state['shared'] + state['srp'].key, state['transcript'])
        return dict(keys, answer=answer)

    def configuration(self, state: dict, keys: dict, session_id: bytes) -> bytes:
        # Only a client that saw the same exchange can open this packet.
        return self.encrypt(keys['server_handshake'], Protocol.configuration, state['identifier'],
                            keys['answer'] + session_id)

    def error_packet(self, state: dict, code: str = 'incorrect_credentials', **details) -> bytes:
        # A stable code: every client interface decides and translates by it.
        return self.reply(state, Protocol.error, errors.encode(code, **details))


class ClientHandshake(Handshake):
    def __init__(self):
        self.private_key, self.identifier = X25519PrivateKey.generate(), os.urandom(16)
        public_key = self.public_bytes(self.private_key.public_key())
        self.keys = self.shared = self.srp = None
        self.packet = Protocol.pack(Protocol.client_hello, self.identifier, public_key)
        self.transcript = b''

    def hello(self) -> bytes:
        return self.packet

    def server_hello(self, packet: bytes):
        details = Protocol.unpack(packet, Protocol.server_hello)
        identifier, content = details[1:3]
        if identifier != self.identifier or len(content) != 32: raise ValueError('Invalid server handshake')
        self.shared = self.private_key.exchange(X25519PublicKey.from_public_bytes(content))
        self.keys = Handshake.keys(self.shared, self.packet + packet)
        self.transcript = self.packet + packet

    def request(self, step: int, content: bytes) -> bytes:
        arguments = self.keys['client_handshake'], Protocol.authentication, self.identifier
        return self.encrypt(*arguments, bytes([step]) + content)

    def answer(self, packet: bytes, expected: int) -> bytes:
        # Errors arrive in the same channel; anything else is refused.
        packet_type, identifier, content = self.decrypt(self.keys['server_handshake'], packet)
        if identifier != self.identifier: raise ValueError('Invalid server handshake')
        if packet_type == Protocol.error: raise errors.VPNError.from_bytes(content)
        if packet_type != expected: raise ValueError('Invalid server handshake')
        return content

    def register(self, username: str, email: str, password: str, iterations: int = None) -> bytes:
        # The password never leaves: only its verifier, computed here.
        record = srp.verifier(password, iterations=iterations)
        fields = (username.encode(), email.encode(), bytes.fromhex(record['salt']),
                  bytes.fromhex(record['verifier']), struct.pack('!I', record['iterations']))
        if any(len(field) > 1024 for field in fields): raise ValueError('The account details are too long')
        return self.request(Steps.register, pack_fields(*fields))

    def registered(self, packet: bytes):
        self.answer(packet, Protocol.registered)

    def login(self, username: str, password: str = None, known: tuple = None) -> bytes:
        if len(username.encode()) > 1024: raise ValueError('The username is too long')
        self.srp = srp.Client(username, password, known=known)
        self.login_packet = self.request(Steps.login, pack_fields(username.encode(), srp.GROUP.pad(self.srp.public)))
        return self.login_packet

    def challenge(self, packet: bytes) -> bytes:
        salt, public_b, iterations = unpack_fields(self.answer(packet, Protocol.challenge), 3)
        if len(iterations) != 4: raise ValueError('Invalid server handshake')
        proof = self.srp.challenge(salt, public_b, struct.unpack('!I', iterations)[0])
        packet_proof = self.request(Steps.proof, pack_fields(proof))
        self.transcript += self.login_packet + packet + packet_proof
        return packet_proof

    def configuration(self, packet: bytes) -> PacketCipher:
        # A wrong password comes back as an error in the ephemeral channel.
        details = Protocol.unpack(packet)
        if details[0] == Protocol.error: self.answer(packet, Protocol.configuration)
        keys = Handshake.keys(self.shared + self.srp.key, self.transcript)
        try: packet_type, identifier, content = self.decrypt(keys['server_handshake'], packet)
        except (InvalidTag, ValueError): raise ValueError('The server could not prove the password')
        valid = identifier == self.identifier and packet_type == Protocol.configuration and len(content) == 48
        # The server proves it holds the verifier: someone in the middle cannot.
        if not valid or not self.srp.verify(content[:32]): raise ValueError('The server could not prove the password')
        return PacketCipher(content[32:], keys['client'], keys['server'], client=True)


class Control:
    # Control messages share the session cipher but never reach the TUN.
    list_networks, connect, disconnected = 'list', 'connect', 'disconnected'
    create_organization, account = 'create_organization', 'account'
    # A quiet tunnel asks now and then; no answer means the server lost the session.
    ping = 'ping'
    # Unlike disconnected, kicked ends the login: the client must not reconnect.
    kicked = 'kicked'
    required = {'network_id', 'mode', 'ip_address', 'subnet_mask',
                'network_range', 'primary', 'routes', 'server'}

    @staticmethod
    def pack(message: dict) -> bytes:
        return json.dumps(message, separators=(',', ':')).encode()

    @staticmethod
    def unpack(content: bytes) -> dict:
        try: message = json.loads(content.decode())
        except (UnicodeDecodeError, json.JSONDecodeError): message = None
        if type(message) is not dict: raise ValueError('Invalid control message')
        return message

    @classmethod
    def networks(cls, networks) -> list[dict]:
        valid = type(networks) is list and len(networks) > 0
        valid = valid and all(type(network) is dict for network in networks)
        valid = valid and all(cls.required <= network.keys() for network in networks)
        valid = valid and sum(bool(network['primary']) for network in networks) == 1
        if not valid: raise ValueError('Invalid network configuration')
        return networks
