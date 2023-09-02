import secrets
import struct
from typing import Optional

from connection import DefaultAuth, network_properties


class NetworkManager:
    def __init__(self, auth_method=DefaultAuth()):
        self.connections, self.accounts, self.network = {}, [], {}
        self.auth_method, self.token_length = auth_method, 10
        self.locked_addresses = lambda: [a[2] for a in self.accounts]

    def new_address(self, default_address: str, address_id: int):
        # Split the default address into a list of integers.
        new_address = list(map(int, default_address.split('.')))
        new_address: list[int] = [*new_address[:-1], address_id]
        # Handle carry-over if necessary (e.g., for IP octets)
        for index in range(4)[::-1]:
            value = new_address[index]
            new_address[index] = value - 255 * (value // 255)
            if index != 0: new_address[index - 1] += value // 255
        # Convert the modified address back to a string.
        return '.'.join(str(n) for n in new_address)

    def assign_address(self, network, account) -> str:
        max_address, addresses = range(network['max_address']), []
        # If the account already has an assigned address, return it.
        if len(account) == 4 and account[3]: return account[3]
        # Get the default address from the network configuration.
        default_address = network['network_range'].split('/')[0]
        # Iterate through address IDs within the maximum range.
        for address_id in max_address:
            ip_address = self.new_address(default_address, address_id)
            connections = network['connections'].keys()
            if ip_address not in connections: return ip_address
        # Raise an exception if the connection limit is reached
        raise Exception('Connection limit reached.')

    def authenticate(self, connection: tuple[bytes, any]) -> tuple:
        # Extract the account from the received packet.
        account = self.auth_method.unpack_credentials(connection[0])
        account = account[0]
        # Iterate through the available accounts to find a match.
        accounts = iter(a for a in self.accounts if a[0] == account)
        credentials = next(accounts, None)
        # If no matching account is found, return authentication failure.
        if not credentials: return False, self.auth_method.error, connection[1]
        status = self.auth_method.check_credentials(credentials, connection[0])
        # Return the authentication status and associated data.
        return status == self.auth_method.success, status, credentials[2]

    def new_network(self, network_range: Optional[tuple or str] = None) -> str:
        token = secrets.token_hex(10)
        ip_address, subnet, network = network_properties(network_range)
        # Create a new network dictionary with the specified properties
        self.network[token] = dict(subnet_mask=subnet, network_range=network)
        self.network[token]['max_address'] = 5
        self.network[token]['connections'] = {}
        # Return the generated token to identify the new network.
        return token

    def add_to_network(self, account: list, connection: tuple[bytes, any]) -> bytes:
        # Define the packet format for the response
        packet_format = f'4s4s{self.token_length}s'
        token = secrets.token_hex(self.token_length).encode()
        network = self.network[account[2]]
        # Assign an IP address to the connection.
        ip_address = self.assign_address(network, account)

        binary_mask = network['subnet_mask'].split('.')
        ip_binary = bytes(map(int, ip_address.split('.')))
        binary_mask = bytes(map(int, binary_mask))
        # Define arguments for struct.pack.
        args = packet_format, ip_binary, binary_mask, token
        account_id = self.accounts.index(account)
        # Update the account information with the assigned
        # IP address.
        if len(account) < 4:
            self.accounts[account_id].append(ip_address)
        self.accounts[account_id][3] = ip_address
        # Manage previous connections and update the network connections.
        previous = self.network[account[2]]['connections'].get(ip_address, None)
        if self.connections.get(ip_address, False) and previous is not None:
            del self.connections[previous]
        self.network[account[2]]['connections'][ip_address] = connection[1]
        # Pack the response packet and return it.
        return struct.pack(*args)
