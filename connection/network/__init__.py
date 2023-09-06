from pymongo import MongoClient

from .accounts import AccountManager
from .connections import ConnectionManager
from .networks import NetworkManager


class Manager:
    def __init__(self, client: MongoClient, db_name: str):
        self.__n_manager = NetworkManager(client, db_name)
        self.__a_manager = AccountManager(client, db_name)
        self.__c_manager = ConnectionManager(client, db_name)
        data_transfer = client[db_name]['data_transfer']
        self.update_transfer = data_transfer.update_one

        self.list_accounts = self.__a_manager.list_objects
        self.new_account = self.__a_manager.new_account
        self.add_to_account = self.__a_manager.add_network
        self.filter_account = self.__a_manager.filter_object
        self.switch_network = self.__a_manager.switch_network

        self.auth_method = self.__c_manager.auth_method

        self.list_networks = self.__n_manager.list_objects
        self.new_network = self.__n_manager.new_network
        self.filter_network = self.__n_manager.filter_object

    def get_connection(self, query: dict) -> dict or None:
        args = 'connections', query, True
        return self.__c_manager.filter_object(*args)

    def new_connection(self, connection: tuple[bytes, any]):
        account = self.__c_manager.authenticate(connection)
        status_success = self.__c_manager.auth_method.success
        if account['status'] != status_success:
            return account['status']
        network_id = account['networks'][0]['id']
        pack_data = self.__c_manager.pack_data
        packet, ip_address = pack_data(account, connection)
        arguments = network_id, account['_id'], ip_address
        self.__n_manager.new_connection(*arguments)
        return packet

    def transfer(self, connection: tuple[bytes, any], is_received: bool = False):
        query = {'connection': ':'.join(map(str, connection[1]))}
        # Get the 'account_id' associated with the connection, or None if not found.
        account_id = (self.get_connection(query) or {}).get('account_id', None)
        # If 'account_id' is None, return None (no transfer data available)
        if account_id is None: return None
        # Find data transfer records associated with the 'account_id'
        query = {'account_id': account_id}
        data_transfer = self.__c_manager.filter_object('data_transfer', query)
        default = dict(account_id=account_id, upload=0, download=0)
        default = data_transfer or default
        # Update the 'download' or 'upload' field of the data transfer records
        default['download' if is_received else 'upload'] += len(connection[0])
        default = {'$set': default}
        # Update the data transfer records in the database, creating a new record
        # if necessary
        self.update_transfer({'account_id': account_id}, default, upsert=True)
