import time

from bson import ObjectId

from connection.protocol import PacketCipher


class Session:
    def __init__(self, account_id: ObjectId, network_id: ObjectId,
                 ip_address: str, connection: tuple,
                 cipher: PacketCipher, subnet_mask: str):
        self.account_id, self.network_id = account_id, network_id
        self.last_packet = time.monotonic()
        self.cipher, self.subnet_mask = cipher, subnet_mask
        self.ip_address, self.connection = ip_address, connection


class SessionRegistry:
    def __init__(self):
        # Index each session by identity, account, and virtual route.
        self.sessions, self.accounts, self.routes = {}, {}, {}

    def add_session(self, session: Session):
        # Replace an account session before publishing its new indexes.
        self.remove_session(session.account_id)
        session_id = session.cipher.session_id
        route = session.network_id, session.ip_address
        self.sessions[session_id] = session
        self.routes[route] = session
        self.accounts[session.account_id] = session_id

    def remove_session(self, account_id: ObjectId):
        session_id = self.accounts.pop(account_id, None)
        session = self.sessions.get(session_id)
        if not session: return
        route = session.network_id, session.ip_address
        self.routes.pop(route, None)
        self.sessions.pop(session_id, None)

    def get_session(self, session_id: bytes):
        return self.sessions.get(session_id)

    def get_route(self, network_id: ObjectId, ip_address: str):
        return self.routes.get((network_id, ip_address))
