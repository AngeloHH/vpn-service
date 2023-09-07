import struct

import bcrypt
from bson import ObjectId
from cryptography.fernet import Fernet
from pymongo import MongoClient

from connection import DefaultAuth


def new_address(default_address: str, address_id: int):
    # Split the default address into a list of integers.
    ip_address = list(map(int, default_address.split('.')))
    ip_address: list[int] = [*ip_address[:-1], address_id]
    # Handle carry-over if necessary (e.g., for IP octets)
    for index in range(4)[::-1]:
        value = ip_address[index]
        ip_address[index] = value - 255 * (value // 255)
        if index != 0: ip_address[index - 1] += value // 255
    # Convert the modified address back to a string.
    return '.'.join(str(n) for n in ip_address)


class ConnectionManager:
    def __init__(self, client: MongoClient, db_name: str):
        self.collection = client[db_name]['connections']
        self.__client = client[db_name]
        self.token_length, self.auth_method = 44, DefaultAuth()

    def filter_object(self, table: str, query: dict, first=True):
        consult = 'find_one' if first else 'find'
        return getattr(self.__client[table], consult)(query)

    def authenticate(self, connection: tuple[bytes, any]):
        unpack_credentials = self.auth_method.unpack_credentials
        credentials = unpack_credentials(connection[0])
        query = {'username': credentials[0]}
        account = self.filter_object('accounts', query)
        if account is None: return {'status': self.auth_method.error}
        password = account['password'].encode()
        check = bcrypt.checkpw(credentials[1].encode(), password)
        status = 'success' if check else 'error'
        account['status'] = getattr(self.auth_method, status)
        return account

    def del_connection(self, account_id: ObjectId):
        return self.collection.delete_many({"account_id": account_id})

    def new_connection(self, account: dict, connection: tuple[bytes, any]):
        query = {'_id': ObjectId(account['networks'][0]['id'])}
        network = self.filter_object('networks', query)
        new_connection = dict(
            connection=':'.join(map(str, connection[1])),
            account_id=account['_id'],
            network_id=network['_id'],
            encrypt=Fernet.generate_key().decode('utf-8')
        )
        self.del_connection(account['_id'])
        self.collection.insert_one(new_connection)
        return new_connection['encrypt'], network

    def assign_address(self, network: dict, account: dict):
        if account['networks'][0]['ip_address'] is not None:
            return account['networks'][0]['ip_address']
        addresses = network.get('connections', {}).values()
        default = network['network_range'].split('/')[0]
        connections = network.get('connections', {})
        account_id = account['_id'].__str__()
        if connections.get(account_id, None) is not None:
            return connections[account['_id'].__str__()]
        for address_id in range(network['max_address']):
            ip_address = new_address(default, address_id)
            if ip_address not in addresses: return ip_address

    def pack_data(self, account: dict, connection: tuple[bytes, any]):
        token, network = self.new_connection(account, connection)
        token = token.encode('utf-8')
        ip_address = self.assign_address(network, account)
        ip_binary = bytes(map(int, ip_address.split('.')))
        packet = f'4s4s{self.token_length}s'
        binary_mask = network['subnet_mask'].split('.')
        binary_mask = bytes(map(int, binary_mask))
        arguments = packet, ip_binary, binary_mask, token
        return struct.pack(*arguments), ip_address
