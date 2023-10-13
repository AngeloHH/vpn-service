import select
import socket
import struct
from threading import Thread
from typing import Optional

import bcrypt
import pytun
from Crypto.Cipher import Salsa20
from bson import ObjectId
from pymongo import MongoClient
from scapy.layers.inet import IP

from connection import DefaultAuth
from connection.database.mongodb import Account, Connection, Network
from connection.monitor import SpeedMonitor


class VPNServer:
    def __init__(self, mongo_client: MongoClient, table_name: str):
        self.table_name = mongo_client[table_name]
        self.token_length = 40
        self.ip_address = '0.0.0.0'
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def algorithm(self, token: bytes or str) -> Salsa20.Salsa20Cipher:
        token = token.encode('utf-8') if type(token) is str else token
        token, nonce = token[:-8], token[-8:]
        return Salsa20.new(key=token, nonce=nonce)

    def unpack(self, packet: bytes) -> tuple[str, bytes]:
        password_end = 3 + packet[1] + packet[2 + packet[1]]
        username = packet[2:2 + packet[1]].decode()
        return username, packet[3 + packet[1]:password_end]

    def pack_data(self, token, ip_address, subnet_mask):
        def to_bytes(i): return bytes(map(int, i.split('.')))
        struct_format = f'4s4s{self.token_length}s'
        arguments = to_bytes(ip_address), to_bytes(subnet_mask), token.encode()
        return struct.pack(struct_format, *arguments)

    def authenticate(self, connection: tuple[bytes, any]):
        username, password = self.unpack(connection[0])
        collection = self.table_name['accounts']
        account = Account(collection).get(username=username)
        credentials = account['password'].encode()
        if bcrypt.checkpw(password, credentials): return account

    def update_transfer(self, account_id: ObjectId or str, length: int):
        account = Account(self.table_name['accounts'], account_id)
        length += account.get().get('transfer_ratio', 0)
        return account.update(transfer_ratio=length)

    def get_destination(self, connection: tuple[bytes, any]):
        collection = self.table_name['connections']
        manager = Connection(collection)
        # Convert the connection tuple into a unique key.
        address = ':'.join(map(str, connection[1]))
        packet = IP(connection[0])
        connection = manager.get(connection=address)
        if not connection: return None
        # Get a list of connections from the network
        network_id = connection['network_id']
        kwargs = dict(network_id=network_id, ip_address=packet.dst)
        return Connection(collection).get(**kwargs)

    def new_configuration(self, connection: dict):
        # Get the collection from the database that stores the network data.
        collection = self.table_name['networks']
        # Get the network data from the database.
        network_id = connection['network_id']
        network = Network(collection, network_id).get()
        subnet_mask = network['subnet_mask']
        token = connection['encrypt']
        ip_address = connection['ip_address']
        # Pack the data into a packet.
        packet = self.pack_data(token, ip_address, subnet_mask)
        client = connection['connection'].split(':')
        self.server.sendto(packet, (client[0], int(client[1])))

    def new_account(self, username: str, password: str):
        password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(10))
        password = password.decode('utf-8')
        kwargs = dict(username=username, password=password, networks={})
        account = Account(self.table_name['accounts']).create(**kwargs)
        return account

    def new_connection(self, connection: tuple[bytes, any]):
        account = self.authenticate(connection)
        if not account: return None
        account_id = account['_id'].__str__()
        # Get the first network key from the account's networks
        network = list(account['networks'].keys())[0]
        collection = self.table_name['networks']
        network = Network(collection, network)
        # Get the IP address associated with the account from
        # the network.
        ip_address = network.get()['connections'][account_id]

        # Create an Account object using the account ID
        collection = self.table_name['accounts']
        account = Account(collection, account_id)

        args = network, account, ip_address, connection[1]
        collection = self.table_name['connections']
        collection.delete_many({'account_id': account.id})
        return Connection(collection).create(*args)

    def send_packet(self, token: bytes, tunnel: bool, connection: tuple[bytes, any]):
        # Decrypt the packet using the token.
        packet = self.algorithm(token).decrypt(connection[0])
        # Get the destination of the packet.
        client = self.get_destination((packet, connection[1]))
        # If the client is not None, then encrypt the packet again
        # and update the transfer status.
        if client is not None:
            # Split the client's connection string into the IP address and port.
            client['connection'] = client['connection'].split(':')
            # Convert the port to an integer.
            client['connection'][1] = int(client['connection'][1])
            # Encrypt the packet using the client's encryption key
            packet = self.algorithm(client['encrypt']).encrypt(packet)
            connection = packet, tuple(client['connection'])
            args = client['account_id'], len(packet)
            # Create a new thread to update the transfer status in the database
            Thread(target=self.update_transfer, args=args, daemon=True).start()
        # If the client is None or the tunnel flag is set, then tunnel the packet.
        elif tunnel:
            port = getattr(IP(packet), 'dport', 0)
            # Update the connection object with the new packet and the destination
            # port.
            connection = packet, (IP(packet).dst, port)
        self.server.sendto(*connection)

    def run_server(self, port: int = 5732, tunnel: bool = False):
        self.server.bind((self.ip_address, port))
        collection = self.table_name['connections']
        while True:
            connection = self.server.recvfrom(65535)
            # Get the data associated with the connection from the database.
            connection_key = ':'.join(map(str, connection[1]))
            data = Connection(collection).get(connection=connection_key)
            # If the data does not exist in the database, then create a new
            # configuration for the connection.
            if not data:
                self.new_configuration(self.new_connection(connection))
                continue
            arguments = data['encrypt'].encode(), tunnel, connection
            Thread(target=self.send_packet, args=arguments, daemon=True).start()
            args = data['account_id'], len(connection[0])
            # Create a new thread to update the transfer status in the database.
            Thread(target=self.update_transfer, args=args, daemon=True).start()


class VPNClient:
    def __init__(self, server_address: Optional[tuple or str] = '192.168.1.0:5732'):
        self.server_address = server_address
        self.speed_monitor = SpeedMonitor()
        # If the server address is provided as a string, parse it into a tuple.
        if type(self.server_address) == str:
            self.server_address = server_address.split(':')
            self.server_address[1] = int(self.server_address[1])
            self.server_address = tuple(self.server_address)
        self.auth_method, self.token_length = DefaultAuth(), 40
        # Set the MTU (Maximum Transmission Unit).
        self.mtu = 1500
        self.connection = [self.server_address[0], '255.255.255.0']
        # Create a UDP socket for server communication.
        self.socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def authenticate(self, username: str, password: str) -> tuple:
        # Define a function to decode IP addresses from bytes.
        def decode(addr): return '.'.join(str(n) for n in map(int, addr))

        # Wrap the provided username and password in an authentication packet
        packet = self.auth_method.wrap_credentials(username, password)
        self.socket_server.sendto(packet, self.server_address)
        # Check if the received packet indicates a failed connection.
        recv_packet, connection = self.socket_server.recvfrom(65535)
        if recv_packet == b'\x03' or len(recv_packet) == 0:
            raise Exception('Connection failed: incorrect credentials')
        # Unpack the received packet to extract decoded data.
        packet = struct.unpack(f'4s4s{self.token_length}s', recv_packet)
        return decode(packet[0]), decode(packet[1]), packet[2]

    def connect(self, credentials: tuple, interface: str):
        # Create a TUN device with the specified interface.
        tun = pytun.TunTapDevice(name=interface, flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        # Authenticate with the provided credentials and set the connection details.
        self.connection = self.authenticate(*credentials)
        # Configure the TUN device with IP address, netmask, token, and MTU.
        tun.addr, tun.netmask, token, tun.mtu = list(self.connection) + [self.mtu]
        token, nonce = token[:len(token) - 8], token[len(token) - 8:]
        print(tun.addr, tun.netmask, token)
        # Enable TUN device persistence and bring it up.
        tun.persist(True), tun.up()
        self.speed_monitor.start_monitoring()
        while True:
            # Monitor I/O sources for the TUN device and the socket server.
            for source in select.select([tun, self.socket_server], [], [])[0]:
                salsa_cipher = Salsa20.new(key=token, nonce=nonce)
                # If the source is the TUN device, read data and send it to
                # the server.
                if type(source) == pytun.TunTapDevice:
                    packet = salsa_cipher.encrypt(source.read(source.mtu))
                    arguments = packet, self.server_address
                    length = self.socket_server.sendto(*arguments)
                    self.speed_monitor.update_transfer(0, length)
                    continue
                # If the source is the socket server, receive data and write
                # it to the TUN device.
                packet_data = salsa_cipher.decrypt(source.recvfrom(65535)[0])
                if len(packet_data) > 0:
                    self.speed_monitor.update_transfer(tun.write(packet_data), 0)
