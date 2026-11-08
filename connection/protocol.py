import os
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Protocol:
    magic, version = b'SVPN', 1
    client_hello, server_hello = 1, 2
    authentication, configuration = 3, 4
    data, error = 5, 6
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
        # Separate ciphers and nonce domains prevent direction collisions.
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.replay = ReplayWindow()
        self.recv_cipher = ChaCha20Poly1305(recv_key)
        self.send_direction = bytes([0, 0, 0, 1 if client else 2])
        self.recv_direction = bytes([0, 0, 0, 2 if client else 1])

    def encrypt(self, packet: bytes) -> bytes:
        # A direction prefix and monotonic counter form the unique nonce.
        counter = self.counter.to_bytes(8, 'big')
        self.counter += 1
        nonce = self.send_direction + counter
        # The complete header is authenticated with the encrypted payload.
        header = Protocol.pack(Protocol.data, self.session_id, counter)
        encrypted = self.send_cipher.encrypt(nonce, packet, header)
        return header + encrypted

    def decrypt(self, packet: bytes) -> bytes:
        # Read the public routing fields before authenticating the payload.
        details = Protocol.unpack(packet, Protocol.data)
        identifier, encrypted, header = details[1:]
        error = 'Invalid encrypted packet'
        invalid = identifier != self.session_id or len(encrypted) < 24
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
    context = b'simple-vpn handshake version 1'

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
        # Bind every derived key to the complete signed transcript.
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


class ServerHandshake(Handshake):
    def __init__(self, private_key: bytes or str = None):
        if type(private_key) is str: private_key = bytes.fromhex(private_key)
        identity = Ed25519PrivateKey
        if private_key: self.identity = identity.from_private_bytes(private_key)
        else: self.identity = identity.generate()
        self.private_key = self.private_bytes(self.identity)
        self.public_key = self.public_bytes(self.identity.public_key())

    def hello(self, packet: bytes) -> tuple:
        # Validate the client hello before creating an ephemeral secret.
        details = Protocol.unpack(packet, Protocol.client_hello)
        identifier, content = details[1:3]
        if len(content) != 32: raise ValueError('The client public key is invalid')
        client_key = X25519PublicKey.from_public_bytes(content)
        private_key = X25519PrivateKey.generate()
        public_key = self.public_bytes(private_key.public_key())
        # Sign both hello packets so the ephemeral exchange is authenticated.
        content = public_key + self.public_key
        unsigned = Protocol.pack(Protocol.server_hello, identifier, content)
        reply = unsigned + self.identity.sign(packet + unsigned)
        shared_key = private_key.exchange(client_key)
        state = dict(identifier=identifier, created=time.monotonic())
        state.update(keys=self.keys(shared_key, packet + reply), reply=reply)
        return reply, state

    def credentials(self, packet: bytes, state: dict) -> tuple:
        # Credentials are accepted only inside the derived handshake channel.
        key = state['keys']['client_handshake']
        details = self.decrypt(key, packet, Protocol.authentication)
        _, identifier, credentials = details
        error = 'Invalid authentication packet'
        invalid = identifier != state['identifier'] or len(credentials) < 3
        if invalid: raise ValueError(error)
        username_length, password_length = struct.unpack('!BH', credentials[:3])
        username = credentials[3:3 + username_length]
        password = credentials[3 + username_length:]
        error = 'Invalid credentials length'
        expected = username_length, password_length
        received = len(username), len(password)
        invalid = received != expected
        if invalid: raise ValueError(error)
        return username.decode(), password.decode()

    def configuration(self, state: dict, ip_address: str,
                      subnet_mask: str, session_id: bytes) -> bytes:
        def to_bytes(address): return bytes(map(int, address.split('.')))
        content = to_bytes(ip_address) + to_bytes(subnet_mask) + session_id
        arguments = state['keys']['server_handshake'], Protocol.configuration
        arguments += state['identifier'], content
        return self.encrypt(*arguments)

    def error_packet(self, state: dict,
                     message: str = 'Incorrect credentials') -> bytes:
        arguments = state['keys']['server_handshake'], Protocol.error
        arguments += state['identifier'], message.encode()
        return self.encrypt(*arguments)


class ClientHandshake(Handshake):
    def __init__(self, server_key: bytes or str):
        if type(server_key) is str: server_key = bytes.fromhex(server_key)
        if not server_key: raise ValueError('The server public key is required')
        self.server_key = Ed25519PublicKey.from_public_bytes(server_key)
        self.private_key, self.identifier = X25519PrivateKey.generate(), os.urandom(16)
        public_key = self.public_bytes(self.private_key.public_key())
        self.keys = None
        self.packet = Protocol.pack(Protocol.client_hello, self.identifier, public_key)

    def hello(self) -> bytes:
        return self.packet

    def server_hello(self, packet: bytes):
        # Verify the pinned identity before accepting ephemeral key material.
        details = Protocol.unpack(packet, Protocol.server_hello)
        identifier, content = details[1:3]
        error = 'Invalid server handshake'
        invalid = identifier != self.identifier or len(content) != 128
        if invalid: raise ValueError(error)
        public_key, identity, signature = content[:32], content[32:64], content[64:]
        expected_key = self.public_bytes(self.server_key)
        error = 'The server identity does not match'
        if identity != expected_key: raise ValueError(error)
        self.server_key.verify(signature, self.packet + packet[:-64])
        # Derive the same directional keys from the verified transcript.
        server_key = X25519PublicKey.from_public_bytes(public_key)
        shared_key = self.private_key.exchange(server_key)
        self.keys = Handshake.keys(shared_key, self.packet + packet)

    def credentials(self, username: str, password: str) -> bytes:
        username, password = username.encode(), password.encode()
        error = 'The credentials are too long'
        invalid = len(username) > 255 or len(password) > 65535
        if invalid: raise ValueError(error)
        header = struct.pack('!BH', len(username), len(password))
        credentials = header + username + password
        arguments = self.keys['client_handshake'], Protocol.authentication
        arguments += self.identifier, credentials
        return self.encrypt(*arguments)

    def configuration(self, packet: bytes) -> tuple:
        details = self.decrypt(self.keys['server_handshake'], packet)
        packet_type, identifier, content = details
        if identifier != self.identifier: raise ValueError('Invalid configuration packet')
        if packet_type == Protocol.error: raise ValueError(content.decode())
        error = 'Invalid configuration packet'
        invalid = packet_type != Protocol.configuration or len(content) != 24
        if invalid: raise ValueError(error)

        def decode(address): return '.'.join(str(n) for n in address)
        ip_address, subnet_mask, session_id = content[:4], content[4:8], content[8:]
        arguments = session_id, self.keys['client'], self.keys['server']
        cipher = PacketCipher(*arguments, client=True)
        return decode(ip_address), decode(subnet_mask), cipher
