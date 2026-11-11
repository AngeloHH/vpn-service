import time
from collections import deque

INFO, WARN, ERROR = 'INFO', 'WARN', 'ERROR'
LIMIT = 500


class Events:
    """Recent events of each organization, kept in memory only.

    An event names what happened (kind) and its fields; the panel turns them
    into text, so the server never stores sentences in one language.
    """

    def __init__(self, limit: int = LIMIT):
        self.limit, self.organizations = limit, {}

    def record(self, organization_id, level: str, kind: str, network_id=None, **fields):
        if not organization_id: return
        events = self.organizations.setdefault(organization_id, deque(maxlen=self.limit))
        network_id = network_id.__str__() if network_id else None
        events.append(dict(time=time.time(), level=level, kind=kind, network_id=network_id, **fields))

    def visible(self, organization_id, allowed) -> list:
        # Newest first; a network event needs status:view on that network.
        events = self.organizations.get(organization_id, ())
        return [event for event in reversed(events) if allowed(event['network_id'])]
