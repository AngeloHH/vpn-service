import select
import socket
import struct
import time
from threading import Thread
from typing import Optional

import pytun
from bson import ObjectId
from cryptography.fernet import Fernet
from pymongo import MongoClient
from scapy.layers.inet import IP

from connection import DefaultAuth
from connection.network import Manager
from connection.monitor import SpeedMonitor


class VPNServer:
    def __init__(self, mongo_client: MongoClient, table_name: str):
        self._is_stopped, self.ip_address = False, '0.0.0.0'
        self.network_manager = Manager(mongo_client, table_name)
        self.max_range = 0

    def stop_server(self): self._is_stopped = True

    def get_destination(self, connection: tuple[bytes, any]):
        # Convert the connection tuple into a unique key.
        key_addr, recv_data = ':'.join(map(str, connection[1])), connection[0]
        connection = self.network_manager.get_connection({'connection': key_addr})
        network = self.network_manager.filter_network(connection['network_id'])
        try: recv_data = Fernet(connection['encrypt']).decrypt(recv_data)
        except: pass
        # Get a list of connections from the network information.
        connections, packet = network['connections'].items(), IP(recv_data)
        # Check if the destination address is not in the list of connections.
        user_id = next((key for key, value in connections if value == packet.dst), None)
        if user_id is None:
            port = packet.dport if hasattr(packet, 'dport') else 0
            return (packet, (packet.dst, port)), True
        destination = self.network_manager.get_connection({'account_id': ObjectId(user_id)})

        # Extract the encryption key from the destination.
        encrypt = destination['encrypt'].encode('utf-8')
        # Encrypt the packet data using the Fernet key.
        recv_data = Fernet(encrypt).encrypt(bytes(packet))
        # Store the destination address (IP and port)
        destination = destination['connection']
        connection = (destination.split(':')[0], int(destination.split(':')[1]))
        # Return a tuple containing the encrypted data and connection information,
        # along with a boolean value 'False' indicating that is not an external connection.
        return [(recv_data, connection), False]

    def recv_packet(self, server: socket, connection: tuple, tunnel: bool):
        key_address = ':'.join(map(str, connection[1]))
        consult = self.network_manager.get_connection
        # If the key address is not in the connections,
        # establish a new connection
        if consult({'connection': key_address}) is None:
            recv_packet = self.network_manager.new_connection(connection)
            return server.sendto(recv_packet, connection[1])
        transfer = self.network_manager.transfer
        Thread(target=transfer, args=(connection,), daemon=True).start()
        # Determine the destination IP address and whether it's
        # external or not. If it's not an external connection or
        # tunneling is enabled, send the packet.
        connection, is_external = self.get_destination(connection)
        if not is_external or tunnel:
            server.sendto(*connection)
            Thread(target=transfer, args=(connection, True), daemon=True).start()
            z = len(connection[0])
            self.max_range = z if self.max_range < z else self.max_range

    def run_server(self, port: int = 5732, tunnel: bool = False):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((self.ip_address, port))
        while True:
            # Check if the server should be stopped.
            if self._is_stopped: break
            connection = server.recvfrom(65535)
            args = (server, connection, tunnel)
            Thread(target=self.recv_packet, args=args, daemon=True).start()


class VPNClient:
    def __init__(self, server_address: Optional[tuple or str] = '192.168.1.0:5732'):
        self.server_address = server_address
        self.speed_monitor = SpeedMonitor()
        # If the server address is provided as a string, parse it into a tuple.
        if type(self.server_address) == str:
            self.server_address = server_address.split(':')
            self.server_address[1] = int(self.server_address[1])
            self.server_address = tuple(self.server_address)
        self.auth_method, self.token_length = DefaultAuth(), 44
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
        print(tun.addr, tun.netmask, token)
        # Enable TUN device persistence and bring it up.
        cipher_suite = Fernet(token)
        tun.persist(True), tun.up()
        self.speed_monitor.start_monitoring()
        while True:
            # Monitor I/O sources for the TUN device and the socket server.
            for source in select.select([tun, self.socket_server], [], [])[0]:
                # If the source is the TUN device, read data and send it to
                # the server.
                if type(source) == pytun.TunTapDevice:
                    packet = cipher_suite.encrypt(source.read(source.mtu))
                    arguments = packet, self.server_address
                    length = self.socket_server.sendto(*arguments)
                    self.speed_monitor.update_transfer(0, length)
                    continue
                # If the source is the socket server, receive data and write
                # it to the TUN device.
                packet_data = cipher_suite.decrypt(source.recvfrom(65535)[0])
                if len(packet_data) > 0:
                    self.speed_monitor.update_transfer(tun.write(packet_data), 0)
