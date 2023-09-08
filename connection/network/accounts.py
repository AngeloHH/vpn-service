import bcrypt
from bson import ObjectId
from pymongo import MongoClient

from connection.network.manager import BaseManager


class AccountManager(BaseManager):
    def __init__(self, client: MongoClient, db_name: str):
        super().__init__(client, db_name, 'accounts')

    def encrypt(self, password: str):
        salt = bcrypt.gensalt(10)
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    def new_account(self, username, password):
        password = self.encrypt(password).decode()
        account = dict(username=username, password=password)
        return self.collection.insert_one(account).inserted_id

    def add_network(self, account_id, network_id, is_owner, address: str = None):
        account = self.collection.find_one({"_id": account_id})
        # Ensure that the 'networks' field exists in the account object.
        if 'networks' not in account:
            account['networks'] = []
        # Check if the network with the specified 'network_id' already
        # exists in the account's networks.
        if not any(network_id == n['id'] for n in account['networks']):
            account['networks'].append({
                'id': network_id,
                'is_owner': is_owner,
                'ip_address': address,
                'is_temporal': address is None
            })
        self.update_object(account)

    def switch_network(self, account_id: ObjectId, network_id):
        # Retrieve the account based on its unique ID.
        account = self.collection.find_one({"_id": account_id})
        networks = account['networks']
        # Determine the index of the network to be switched based
        # on its ID.
        for index, network in enumerate(networks):
            if type(network_id) == int:
                break
            if network['id'] == network_id:
                network_id = index
        # Move the selected network to the beginning of the list.
        account['networks'].insert(0, networks.pop(network_id))
        self.update_object(account)
