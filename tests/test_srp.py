import unittest

from connection import srp

# Values computed independently with pysrp in RFC 5054 mode (2048-bit group, SHA-256).
A_SECRET = int.from_bytes(bytes(range(1, 33)) * 8, 'big')
B_SECRET = int.from_bytes(bytes(range(33, 65)) * 8, 'big')
SALT = bytes.fromhex('beb25379d1a8581eb5a727673a2441ee')
X = 0x65ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303
VERIFIER = bytes.fromhex(
    '400272a61e185e23784e28a16a149dc60a3790fd45856f79a7070c44f7da1ca22f711cd5bc3592171a875c7812472916'
    'de2dcfafc22f7dead8f578f1970547936f9eec686bb3df66ff57f724f6b907e83530812b4ffdbf614153e9fbfed4fc6d'
    '972da70bb23f6ccd36ad08b72567fe6bcd2bacb713f2cdb9dc8f81f897f489bb393067d66237a3e061902e72096d5ac1'
    'cd1d06c1cd648f7e56da5ec6e0094c1b448c5d63ad2addec1e3d9a3aa7118a0410e53434ddbffc60eef5b82548bda5a2'
    'f513209484d3221982ca74668a4d37330cc9cfe3b10f0db368293e43026e3a01440ac732bc1cfb983b512d10296f6951'
    'ec5e567329af8e58d7c21ea6c778b0bd')
PUBLIC_B = bytes.fromhex(
    '79cc0941cc3897946e117d684a6cb46d7cb564b7845be1923b8aa01f709fc9f9e585a41a592f7bc65ead2d7655ed653f'
    '79baad8dd09d293f66b2c54270fdf1fd875256f2d2f0fcc9098c958830a61a248138963d503b5ed2819d1d35dcf00eed'
    'b2fc5ac3bf83e4b8b9b8522a23b3f80627de702db135319f9068b2ad097c8fb672b9935d0dcaeac0b51a49bd40928b83'
    'ac5ba06e432b5f61ad3d18668382e3d3c9d49d37db6488fb8fe886269d7472add17d533235e5dbc35cfbddeddcc8e98f'
    '5c1f5b11741fb618f7a9ab5c7a7d1c1d0a191f8795d8a38d88a3a9083c34391254be7814fa0ae6542ecb1790da94bafa'
    'c7e95dfb20de673b15fabfa20b3e7e02')
KEY = bytes.fromhex('afdf3c15be7f4c62d5977ceb1c53815204c860bedc340a043375ec65f445ac2a')


class SRPTest(unittest.TestCase):
    def test_both_sides_match_an_independent_implementation(self):
        client = srp.Client('alice', 'unused', secret=A_SECRET)
        server = srp.Server('alice', SALT, VERIFIER, srp.pad(client.public), secret=B_SECRET)
        self.assertEqual(srp.pad(server.public), PUBLIC_B)
        self.assertEqual(server.key, KEY)
        proof = client.challenge(SALT, PUBLIC_B, x=X)
        self.assertEqual(client.key, KEY)
        answer = server.verify(proof)
        self.assertTrue(client.verify(answer))

    def test_a_wrong_password_fails_on_both_sides(self):
        record = srp.verifier('right password')
        salt, verifier = bytes.fromhex(record['salt']), bytes.fromhex(record['verifier'])
        client = srp.Client('alice', 'wrong password')
        server = srp.Server('alice', salt, verifier, srp.pad(client.public))
        proof = client.challenge(salt, srp.pad(server.public), record['iterations'])
        self.assertIsNone(server.verify(proof))
        # An impostor without the verifier cannot answer the client either.
        client = srp.Client('alice', 'right password')
        impostor = srp.Server('alice', salt, bytes.fromhex(srp.verifier('guess', salt)['verifier']),
                              srp.pad(client.public))
        proof = client.challenge(salt, srp.pad(impostor.public), record['iterations'])
        self.assertIsNone(impostor.verify(proof))
        self.assertFalse(client.verify(b'\0' * 32))

    def test_degenerate_public_values_are_refused(self):
        record = srp.verifier('password')
        salt, verifier = bytes.fromhex(record['salt']), bytes.fromhex(record['verifier'])
        for value in (0, srp.N, 2 * srp.N):
            with self.assertRaises(ValueError): srp.Server('alice', salt, verifier, srp.pad(value, 512))
            with self.assertRaises(ValueError):
                srp.Client('alice', 'password').challenge(salt, srp.pad(value, 512), record['iterations'])

    def test_the_server_may_not_choose_a_cheap_or_endless_stretch(self):
        client = srp.Client('alice', 'password')
        for iterations in (None, srp.MINIMUM - 1, srp.MAXIMUM + 1, '1000'):
            with self.assertRaises(ValueError): client.challenge(b'salt' * 4, srp.pad(5), iterations)

    def test_records_are_checked_before_they_are_stored(self):
        record = srp.verifier('password')
        self.assertTrue(srp.valid(record))
        self.assertTrue(srp.check('password', record))
        self.assertFalse(srp.check('Password', record))
        broken = [None, {}, dict(record, salt='zz'), dict(record, salt='00' * 8), dict(record, verifier='00' * 256),
                  dict(record, verifier=record['verifier'][:-2]), dict(record, iterations=srp.MINIMUM - 1),
                  dict(record, iterations=str(record['iterations'])), dict(record, verifier=srp.pad(srp.N - 1).hex())]
        for item in broken:
            with self.subTest(item=item): self.assertFalse(srp.valid(item))
        self.assertFalse(srp.check('password', None))

    def test_unknown_names_get_a_stable_invented_record(self):
        secret = b's' * 32
        self.assertEqual(srp.fake(secret, 'ghost'), srp.fake(secret, 'ghost'))
        self.assertNotEqual(srp.fake(secret, 'ghost')['salt'], srp.fake(secret, 'other')['salt'])
        self.assertNotEqual(srp.fake(secret, 'ghost'), srp.fake(b't' * 32, 'ghost'))
        self.assertTrue(srp.valid(srp.fake(secret, 'ghost')))


if __name__ == '__main__': unittest.main()
