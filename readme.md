# Simple VPN

This project consists of a client and server VPN that allows you to create virtual networks without the need to create new network interfaces on the server. It was primarily developed to enhance my skills in socket programming, thread management, and selectors. The client creates its virtual network card with the system's own TUN on Linux (/dev/net/tun) and macOS (utun), and with Wintun on Windows; user and network information is stored in a MongoDB database.

<p style="text-align: center">
<img src="./network_picture.png" alt="network-picture">
</p>

## Server Features
- Credential Security: Passwords never leave the client and are not stored: the server keeps only an SRP verifier.
- Transfer Statistics: Real-time statistics on the data transfer rate for each user account.
- In-Memory Routing: Authenticated sessions and virtual routes stay in memory, so packets do not query MongoDB while being forwarded.
- Multi-Network Sessions: One encrypted connection can enter several virtual networks through a single client TUN interface.
- Flexible Network Identity: A membership can reserve an independent address or reuse an address assigned by another network.
- Independent Virtual Networks: Each created network is independent, increasing user privacy.
- Authenticated Encryption: Every packet uses ChaCha20-Poly1305 with a unique counter, an authentication tag, and replay protection.
- Password Handshake: SRP-6a proves the password on both sides, so clients only need the server address and port.

## Future Features
- Full Routing: Implementing the ability to access any address from the VPN client when the server has this feature enabled.
- Add a transfer rate limit: Implementing a maximum data transfer speed for VPN connections.

## How to Create a Server
You can create a VPN server as follows:

```python
from pymongo import MongoClient
from connection import VPNServer

client = MongoClient("mongodb://localhost:27017/")
# public=True lets anyone create an account from the client.
vpn_server = VPNServer(client, 'test_network', public=True)
# Optionally, you can specify an IP address.
vpn_server.ip_address = '127.0.0.1'
vpn_server.run_server(port=5732)
```

From the command line, `python -m connection serve --public` does the same and
keeps its secret in `server.key`. On a server without `--public`, the operator
creates each account with `python -m connection account <username> <email>`.

## How to Connect to the Server
To connect to the VPN server, you can follow these steps:

```python
from connection import VPNClient, VPNError

# Only the server's address and port are needed.
vpn_client = VPNClient(('127.0.0.1', 5732))
# Once, on a public server: the password itself is never sent.
vpn_client.register('username', 'user@example.com', 'password123*')
vpn_client.authenticate('username', 'password123*')
if not vpn_client.list_networks():
    # A new account has no networks: it founds an organization, or waits until
    # an administrator adds its email to one from the panel.
    vpn_client.create_organization('My organization')
vpn_client.connect(interface='my_interface')
```

Code, a command line and a visual interface use these same calls. Every failure
they must handle is a `VPNError` whose `code` is stable (`no_networks`,
`incorrect_credentials`, `username_taken`, `too_many_attempts`, ...) and whose
`details` carry any numbers, such as `wait`. `connection.errors.MESSAGES` lists
every code with a default English text, so each interface can translate by code.

### From the command line

The same steps, over the same calls:

```
python -m connection register vpn.example.com ana ana@example.com
python -m connection networks vpn.example.com ana
python -m connection organization vpn.example.com ana "My organization"
python -m connection connect vpn.example.com ana --interface vpn0
```

The server is `host` or `host:port` (5732 by default). Passwords are typed at a
prompt, or read from one line of standard input with `--password-stdin`. When the
account has no networks, `register` and `connect` offer to found an organization;
`--create-organization NAME` does it without asking. A command ends with 0 when it
succeeds, 1 on an error (shown with its code) and 3 when the account has no
networks and waits to be added to one. If the server restarts or stops answering,
`connect` keeps the network card and logs in again by itself (with the stretched
password value, never the password) as soon as the server is back.
`connect` needs administrator rights to
create the network card; on Windows it also needs `wintun.dll` (inside the
executable, beside it, or where the `VPN_WINTUN` variable points).

### Desktop application

A window with the panel's look (light and dark themes; Spanish, English, Chinese
and Russian) over the same calls: log in, create an account, found an
organization or wait to be added, choose a network, connect and disconnect, and
open the network's panel.

```
pip install -r requirements-desktop.txt
python -m connection.desktop
```

The server and username are remembered; the password never is.

### One executable

```
pip install -r requirements-build.txt
python build.py                        # dist/VPN (VPN.exe on Windows)
python build.py --wintun C:\path\wintun.dll   # Windows, without internet
```

The same executable opens the window when it has no arguments and runs the
commands when it has them (`VPN register ...`, `VPN connect ...`). Each system
builds its own (Windows on Windows, macOS on macOS). On Windows it carries
`wintun.dll` inside, and its manifest asks for no console of its own: on
Windows 11 24H2 and later a double click opens only the window; older versions
show a console for a moment, which the window hides. Opened with a double click
it asks once for administrator rights; from a terminal the commands print and
return their exit codes as usual (`connect` needs an administrator terminal). Without `--wintun`, Wintun 0.14.1 is downloaded from
wintun.net, its Authenticode signature is checked and its SHA-256 is shown so it
can be pinned with `--wintun-sha256`. With `--wintun`, the given `.dll` (or the
Wintun `.zip`) is used as it is and nothing is downloaded; it must match the
architecture being built.

## Multiple Network Access

An account keeps one encrypted session even when it can access several networks.
The client places all assigned addresses and preferred routes on the same TUN
interface. A network membership supports two modes:

- `assigned`: the target network reserves and exposes its own address.
- `routed`: the target network exposes an address already assigned by another
  network and does not reserve an additional address.

```python
from connection.database.mongodb import Account, Network

account = Account(database['accounts'], account_id)
primary = Network(database['networks'], primary_network_id)
secondary = Network(database['networks'], secondary_network_id)

# The first option gives the account a different address in each network.
primary.to_network(account, mode='assigned', primary=True)
secondary.to_network(account, mode='assigned')

# Use this instead when the secondary network must see the primary address.
secondary.to_network(account, mode='routed', source_network=primary.id)
```

Routed identities require the target network's return traffic to pass through
the VPN server. Networks attached to the same single TUN interface must use
different ranges; duplicate ranges are rejected when the session is created.
Membership changes take effect when the affected clients reconnect.

## Virtual Network HTTP Server

Each virtual network can expose an HTTP server that exists entirely inside the
VPN process. TCP is handled in memory by `tcp-sansio`; the operating system does
not open a TCP port or create a server-side TUN adapter.

```python
http = vpn_server.add_virtual_http(
    network_id, ip_address='192.168.1.1', port=80
)

@http.route('GET', '/')
def index(request):
    return 'Virtual router'
```

The address and port are stored in the network record, reserved from future
client leases, and included in the encrypted configuration sent at login. Data
packets still use the existing UDP tunnel and do not query MongoDB.

## Packet Protocol

The handshake takes place over the same UDP socket. An ephemeral X25519 exchange
hides everything that follows. Registration sends the username, the email and an
SRP verifier computed by the client (PBKDF2-SHA256 over the password). A login
runs SRP-6a on the 2048-bit group of RFC 5054: both sides prove the password
without sending it, and HKDF derives independent client-to-server and
server-to-client keys from the X25519 secret, the SRP key and the whole
transcript. Someone relaying in the middle can neither read the traffic nor
finish the login. The only exposed moment is the registration itself, if an
impostor answers it: it would see the verifier, never the password.

Unknown usernames receive an invented but stable challenge, so the answers do
not reveal who has an account. Repeated failures from a name or an address wait
longer each time, and an address creates at most five accounts per hour.

The server returns the complete encrypted membership list, including assigned
addresses, routed identities, network ranges, and return routes.

Each data packet contains the protocol identifier, version, packet type, a random
session ID, and a 64-bit packet counter. The header is authenticated together with
the encrypted IP packet. Counters are accepted through a sliding window so UDP
packets can arrive out of order without allowing a packet to be replayed.
