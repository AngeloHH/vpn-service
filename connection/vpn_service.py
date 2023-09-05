import select
import socket
import struct
from typing import Optional

import pytun
from bson import ObjectId
from pymongo import MongoClient
from scapy.layers.inet import IP

from connection import DefaultAuth
from connection.network import Manager


class VPNServer:
    def __init__(self, mongo_client: MongoClient, table_name: str):
        self._is_stopped, self.ip_address = False, '0.0.0.0'
        self.network_manager = Manager(mongo_client, table_name)

    def stop_server(self): self._is_stopped = True

    def get_destination(self, connection: tuple[bytes, any]):
        # Convert the connection tuple into a unique key.
        key_addr = ':'.join(map(str, connection[1]))
        packet = IP(connection[0])
        connection = self.network_manager.get_connection({'connection': key_addr})
        network = self.network_manager.filter_network(connection['network_id'])
        # Get a list of connections from the network information.
        connections = network['connections'].items()
        # Check if the destination address is not in the list of connections.
        user_id = next((key for key, value in connections if value == packet.dst), None)
        if user_id is None:
            port = packet.dport if hasattr(packet, 'dport') else 0
            return (packet.dst, port), True
        consult = {'account_id': ObjectId(user_id)}
        destination = self.network_manager.get_connection(consult)
        destination = destination['connection'].split(':')
        return (destination[0], int(destination[1])), False

    def run_server(self, port: int = 5732, tunnel: bool = False):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((self.ip_address, port))
        while True:
            # Check if the server should be stopped.
            if self._is_stopped: break
            connection = server.recvfrom(65535)
            print(connection)
            key_address = ':'.join(map(str, connection[1]))
            # If the key address is not in the connections,
            # establish a new connection
            consult = self.network_manager.get_connection
            if consult({'connection': key_address}) is None:
                recv_packet = self.network_manager.new_connection(connection)
                server.sendto(recv_packet, connection[1])
                continue
            # Determine the destination IP address and whether it's
            # external or not. If it's not an external connection or
            # tunneling is enabled, send the packet.
            ip_address, is_external = self.get_destination(connection)
            if not is_external or tunnel:
                length = server.sendto(connection[0], ip_address)


class VPNClient:
    def __init__(self, server_address: Optional[tuple or str] = '192.168.1.0:5732'):
        self.server_address = server_address
        # If the server address is provided as a string, parse it into a tuple.
        if type(self.server_address) == str:
            self.server_address = server_address.split(':')
            self.server_address[1] = int(self.server_address[1])
            self.server_address = tuple(self.server_address)
        self.auth_method, self.token_length = DefaultAuth(), 10
        # Set the MTU (Maximum Transmission Unit).
        self.mtu, self.transferred = 1500, [0, 0]
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
        tun.persist(True), tun.up()
        while True:
            # Monitor I/O sources for the TUN device and the socket server.
            for source in select.select([tun, self.socket_server], [], [])[0]:
                # If the source is the TUN device, read data and send it to
                # the server.
                if type(source) == pytun.TunTapDevice:
                    arguments = source.read(tun.mtu), self.server_address
                    self.transferred[1] = self.socket_server.sendto(*arguments)
                    print(arguments[0])
                    continue
                # If the source is the socket server, receive data and write it
                # to the TUN device.
                packet_data, _ = source.recvfrom(65535)
                if len(packet_data) > 0:
                    print(packet_data)
                    self.transferred[0] = tun.write(packet_data)
