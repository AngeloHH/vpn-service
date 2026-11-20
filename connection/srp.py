import hashlib
import hmac
import os

# SRP-6a: the password proves both sides without ever crossing the network.
# The 2048-bit group comes from RFC 5054; the hash is SHA-256.
N = int(
    'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A0'
    '99ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A'
    '163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041'
    'D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32'
    'E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF87'
    '4E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435'
    'DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73', 16)
G = 2
SIZE = (N.bit_length() + 7) // 8
# The client stretches the password: a stolen verifier costs this much per guess.
# The count travels with the salt, so it can rise later without breaking accounts.
ITERATIONS, MINIMUM, MAXIMUM = 600_000, 100_000, 10_000_000
SALT = 16


def pad(number: int, size: int = SIZE) -> bytes:
    return number.to_bytes(size, 'big')


def digest(*parts: bytes, hash_name: str = 'sha256') -> bytes:
    hashed = hashlib.new(hash_name)
    for part in parts: hashed.update(part)
    return hashed.digest()


class Group:
    def __init__(self, n: int = N, g: int = G, hash_name: str = 'sha256'):
        self.n, self.g, self.hash_name = n, g, hash_name
        self.size = (n.bit_length() + 7) // 8
        self.k = self.number(self.pad(n), self.pad(g))
        # H(N) xor H(g), part of the client proof.
        self.ng = bytes(a ^ b for a, b in zip(self.hash(self.pad(n)), self.hash(self.pad(g))))

    def pad(self, number: int) -> bytes: return pad(number, self.size)

    def hash(self, *parts: bytes) -> bytes: return digest(*parts, hash_name=self.hash_name)

    def number(self, *parts: bytes) -> int: return int.from_bytes(self.hash(*parts), 'big')

    def secret(self) -> int:
        # 256 random bits: far more than any guess can reach.
        return int.from_bytes(os.urandom(32), 'big')

    def scramble(self, public_a: int, public_b: int) -> int:
        return self.number(self.pad(public_a), self.pad(public_b))

    def proof(self, username: bytes, salt: bytes, public_a: int, public_b: int, key: bytes) -> bytes:
        return self.hash(self.ng, self.hash(username), salt, self.pad(public_a), self.pad(public_b), key)

    def answer(self, public_a: int, proof: bytes, key: bytes) -> bytes:
        return self.hash(self.pad(public_a), proof, key)


GROUP = Group()


def stretch(password: str, salt: bytes, iterations: int) -> int:
    derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return int.from_bytes(derived, 'big')


def verifier(password: str, salt: bytes = None, iterations: int = None,
             group: Group = GROUP) -> dict:
    # Computed by whoever knows the password; the server stores only this.
    salt, iterations = salt or os.urandom(SALT), iterations or ITERATIONS
    value = group.pad(pow(group.g, stretch(password, salt, iterations), group.n))
    return dict(salt=salt.hex(), verifier=value.hex(), iterations=iterations)


def valid(record) -> bool:
    # What an account stores, as it arrives from a client registering.
    try:
        salt, value = bytes.fromhex(record['salt']), int(record['verifier'], 16)
        iterations = record['iterations']
    except (KeyError, TypeError, ValueError): return False
    return (SALT <= len(salt) <= 64 and len(record['verifier']) == SIZE * 2 and 1 < value < N - 1
            and type(iterations) is int and MINIMUM <= iterations <= MAXIMUM)


def check(password: str, record: dict) -> bool:
    # Inside the authenticated tunnel the panel sends the password itself; it is compared here.
    if not valid(record): return False
    expected = verifier(password, bytes.fromhex(record['salt']), record['iterations'])['verifier']
    return hmac.compare_digest(expected, record['verifier'])


def fake(secret: bytes, username: str) -> dict:
    # An unknown name gets a stable invented record: the answer does not reveal who exists.
    salt = hmac.new(secret, b'salt:' + username.encode(), 'sha256').digest()[:SALT]
    exponent = int.from_bytes(hmac.new(secret, b'verifier:' + username.encode(), 'sha256').digest(), 'big')
    return dict(salt=salt.hex(), verifier=GROUP.pad(pow(G, exponent, N)).hex(), iterations=ITERATIONS)


class Client:
    def __init__(self, username: str, password: str = None, group: Group = GROUP, secret: int = None,
                 known: tuple = None):
        # known: (salt, iterations, x) of an earlier login, to log in again without the password.
        self.group, self.username, self.password, self.known = group, username.encode(), password, known
        self.a = secret or group.secret()
        self.public = pow(group.g, self.a, group.n)
        self.key = self.expected = self.stretched = None

    def challenge(self, salt: bytes, public_b: bytes, iterations: int = None, x: int = None) -> bytes:
        # The server's answer to the public value; the proof shows the password.
        group, public_b = self.group, int.from_bytes(public_b, 'big')
        if public_b % group.n == 0: raise ValueError('Invalid server value')
        u = group.scramble(self.public, public_b)
        if u == 0: raise ValueError('Invalid server value')
        if x is None and self.known and self.known[:2] == (salt, iterations): x = self.known[2]
        if x is None:
            if type(iterations) is not int or not MINIMUM <= iterations <= MAXIMUM:
                raise ValueError('Invalid server value')
            # Remembered only as this stretched value, never as the password.
            if self.password is None: raise LookupError('The account changed its password')
            x = stretch(self.password, salt, iterations)
        self.stretched = salt, iterations, x
        base = (public_b - group.k * pow(group.g, x, group.n)) % group.n
        self.key = group.hash(group.pad(pow(base, self.a + u * x, group.n)))
        proof = group.proof(self.username, salt, self.public, public_b, self.key)
        self.expected = group.answer(self.public, proof, self.key)
        return proof

    def verify(self, answer: bytes) -> bool:
        # The server proves it holds the verifier: an impostor cannot.
        return self.expected is not None and hmac.compare_digest(answer, self.expected)


class Server:
    def __init__(self, username: str, salt: bytes, verifier_bytes: bytes, public_a: bytes,
                 group: Group = GROUP, secret: int = None):
        self.group, self.username, self.salt = group, username.encode(), salt
        public_a = int.from_bytes(public_a, 'big')
        if public_a % group.n == 0: raise ValueError('Invalid client value')
        v, self.b = int.from_bytes(verifier_bytes, 'big'), secret or group.secret()
        self.public_a = public_a
        self.public = (group.k * v + pow(group.g, self.b, group.n)) % group.n
        u = group.scramble(public_a, self.public)
        if u == 0: raise ValueError('Invalid client value')
        self.premaster = pow(public_a * pow(v, u, group.n), self.b, group.n)
        self.key = group.hash(group.pad(self.premaster))

    def verify(self, proof: bytes) -> bytes or None:
        # Only a client that knows the password reaches the same proof.
        group = self.group
        expected = group.proof(self.username, self.salt, self.public_a, self.public, self.key)
        if not hmac.compare_digest(proof, expected): return None
        return group.answer(self.public_a, proof, self.key)
