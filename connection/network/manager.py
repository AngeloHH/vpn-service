from bson import ObjectId
from pymongo import MongoClient


class BaseManager:
    def __init__(self, client: MongoClient, db_name: str, table_name: str):
        self.collection = client[db_name][table_name]

    def filter_object(self, query: dict, first: bool = True):
        consult = 'find_one' if first else 'find'
        return getattr(self.collection, consult)(query)

    def list_objects(self, skip: int = 0, limit: int = 100):
        return self.collection.find().skip(skip).limit(limit)

    def update_object(self, object_data):
        object_id = ObjectId(object_data['_id'])
        del object_data['_id']
        self.collection.update_one({"_id": object_id}, {"$set": object_data})
