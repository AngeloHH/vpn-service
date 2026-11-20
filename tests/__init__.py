from connection import srp
from connection.protocol import ClientHandshake

# Tests stretch passwords briefly; real accounts use the full count.
srp.ITERATIONS = srp.MINIMUM = 1000
PASSWORD = 'password123*'
RECORD = srp.verifier(PASSWORD)


def login(server, address, username: str = 'username', password: str = PASSWORD):
    # The whole exchange through the server's handshake handler.
    client = ClientHandshake()
    server.receive_handshake((client.hello(), address))
    client.server_hello(server.server.packets.pop()[0])
    server.receive_handshake((client.login(username, password), address))
    proof = client.challenge(server.server.packets.pop()[0])
    server.receive_handshake((proof, address))
    return client.configuration(server.server.packets.pop()[0])
