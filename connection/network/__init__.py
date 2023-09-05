from pymongo import MongoClient

from .accounts import AccountManager
from .connections import ConnectionManager
from .networks import NetworkManager


class Manager:
    def __init__(self, client: MongoClient, db_name: str):
        self.__n_manager = NetworkManager(client, db_name)
        self.__a_manager = AccountManager(client, db_name)
        self.__c_manager = ConnectionManager(client, db_name)

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
