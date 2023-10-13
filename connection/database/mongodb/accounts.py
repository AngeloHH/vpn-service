from bson import ObjectId
from pymongo.collection import Collection


class Account:
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        if _id is not None:
            self.id = _id if type(_id) == ObjectId else ObjectId(_id)
        self.collection = collection

    def get(self, **kwargs):
        return self.collection.find_one(kwargs or {'_id': self.id})

    def create(self, **kwargs):
        kwargs['id'] = self.collection.insert_one(kwargs).inserted_id
        [setattr(self, key, value) for key, value in kwargs.items()]
        return kwargs

    def delete(self, **kwargs):
        return self.collection.delete_one(kwargs or {'_id': self.id})

    def filter(self, skip: int = 0, limit: int = 100, **kwargs):
        return self.collection.find(kwargs).skip(skip).limit(limit)

    def update(self, **kwargs):
        self.collection.update_one({"_id": self.id}, {"$set": kwargs})
        return self.get()
