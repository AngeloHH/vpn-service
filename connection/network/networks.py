from bson import ObjectId
from pymongo import MongoClient

from connection import network_properties
from connection.network.manager import BaseManager


class NetworkManager(BaseManager):
    def __init__(self, client: MongoClient, db_name: str):
        super().__init__(client, db_name, 'networks')

    def new_network(self, network_range: str or tuple, max_address: int):
        _, subnet_mask, network_range = network_properties(network_range)
        network = dict(max_address=max_address)
        data = dict(network_range=network_range, subnet_mask=subnet_mask)
        return self.collection.insert_one({**network, **data}).inserted_id

    def new_connection(self, network_id: str, account_id: str, address):
        update = {f"connections.{account_id}": address}
        query = {"_id": ObjectId(network_id)}
        network = self.filter_object(query, True)
        for account, ip_address in network.get("connections", {}).items():
            if ip_address == address or account == account_id:
                continue
            update[f'connections.{account}'] = ip_address
        consult = [{"$set": {"connections": {}}}, {"$set": update}]
        self.collection.update_one(query, consult, upsert=True)
