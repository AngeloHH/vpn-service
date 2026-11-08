# Simple VPN

This project consists of a client and server VPN that allows you to create virtual networks without the need to create new network interfaces on the server. It was primarily developed to enhance my skills in socket programming, thread management, and selectors. To create virtual network interfaces on the client side, the pytun library is used, and user and network information is stored in a MongoDB database.

<p style="text-align: center">
<img src="./network_picture.png" alt="network-picture">
</p>

## Server Features
- Credential Security: User passwords are not stored in plain text, ensuring enhanced security.
- Transfer Statistics: Real-time statistics on the data transfer rate for each user account.
- In-Memory Routing: Authenticated sessions and virtual routes stay in memory, so packets do not query MongoDB while being forwarded.
- Independent Virtual Networks: Each created network is independent, increasing user privacy.
- Authenticated Encryption: Every packet uses ChaCha20-Poly1305 with a unique counter, an authentication tag, and replay protection.
- Secure Handshake: X25519 creates ephemeral traffic keys and Ed25519 verifies the identity of the VPN server before credentials are sent.

## Future Features
- Full Routing: Implementing the ability to access any address from the VPN client when the server has this feature enabled.
- Add a transfer rate limit: Implementing a maximum data transfer speed for VPN connections.

## How to Create a Server
You can create a VPN server as follows:

```python
from pymongo import MongoClient
from connection import VPNServer

client = MongoClient("mongodb://localhost:27017/")
# On the first run this value can be None. Save vpn_server.private_key
# securely and replace it here so that the server keeps the same identity.
private_key = None
vpn_server = VPNServer(client, 'test_network', private_key)
# Optionally, you can specify an IP address.
vpn_server.ip_address = '127.0.0.1'
print('Client public key:', vpn_server.public_key)
vpn_server.run_server(port=5732)
```

## How to Connect to the Server
To connect to the VPN server, you can follow these steps:

```python
from connection import VPNClient

# Specify the server's address, port, and previously verified public key.
server_key = 'server-public-key-in-hexadecimal'
vpn_client = VPNClient(('127.0.0.1', 5732), server_key)
# Replace with the appropriate credentials.
credentials = 'Username', 'password123*'
vpn_client.connect(credentials, 'my_interface')
```

## Packet Protocol

The handshake takes place over the same UDP socket in three exchanges. The client
creates an ephemeral X25519 key, verifies the server's Ed25519 signature, and then
sends its credentials encrypted. HKDF derives independent client-to-server and
server-to-client keys without sending them through the network.

Each data packet contains the protocol identifier, version, packet type, a random
session ID, and a 64-bit packet counter. The header is authenticated together with
the encrypted IP packet. Counters are accepted through a sliding window so UDP
packets can arrive out of order without allowing a packet to be replayed.
