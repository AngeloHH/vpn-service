from bson import ObjectId
from pymongo.collection import Collection

from .accounts import Account


class Organization(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)

    def create(self, name: str = None):
        # A name only helps people tell organizations apart.
        return super().create(name=name)


class Role(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)


class Member(Account):
    def __init__(self, collection: Collection, _id: str or ObjectId = None):
        super().__init__(collection, _id)
