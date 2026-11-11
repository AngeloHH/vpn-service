import queue
import time


def current_period(now: float = None) -> str:
    # Quotas restart on the first day of each month, in the server's time zone.
    return time.strftime('%Y-%m', time.localtime(now))


class Usage:
    """Bytes each person spent this month, per network and on the internet.

    The packet path only adds to counters in memory. Every few seconds the
    loop hands the new bytes to a writer thread, which adds them to MongoDB,
    so a restart keeps the month's consumption.
    """

    def __init__(self, collection, interval: float = 5, clock=time.time):
        # collection() returns the MongoDB collection, read only when first needed.
        self.collection, self.interval, self.clock = collection, interval, clock
        self.period = current_period(clock())
        # key = (organization_id, account_id, scope): scope is a network id or 'internet'.
        self.totals, self.pending, self.notices = {}, {}, set()
        # Bytes added to a quota until the month ends; key = (organization_id, kind, id, scope),
        # kind 'account' or 'role'. Only extras loaded or granted while running are here.
        self.extras = {}
        self.writes, self.last = queue.Queue(), clock()

    def spent(self, key: tuple) -> list:
        # Loaded once from MongoDB; afterwards the counter in memory is the truth.
        if key not in self.totals:
            organization_id, account_id, scope = key
            stored = self.collection().find_one(dict(organization_id=organization_id, account_id=account_id,
                                                   scope=scope, period=self.period)) or {}
            self.totals[key] = [stored.get('down', 0), stored.get('up', 0)]
        return self.totals[key]

    def load_extra(self, key: tuple) -> list:
        # Called when connecting, never on the packet path.
        if key not in self.extras:
            organization_id, kind, owner, scope = key
            stored = self.collection().find_one(self.extra_query(key)) or {}
            self.extras[key] = [stored.get('extra_down', 0), stored.get('extra_up', 0)]
        return self.extras[key]

    def extra(self, key: tuple, index: int) -> int:
        counter = self.extras.get(key)
        return counter[index] if counter else 0

    def set_extra(self, key: tuple, values: list):
        # Loop thread: the totals the writer already stored for this month.
        self.extras[key] = list(values)

    def extra_query(self, key: tuple, period: str = None) -> dict:
        organization_id, kind, owner, scope = key
        return {'organization_id': organization_id, f'{kind}_id': owner, 'scope': scope,
                'period': period or self.period}

    def add(self, key: tuple, index: int, size: int):
        self.spent(key)[index] += size
        self.pending.setdefault(key, [0, 0])[index] += size

    def first_notice(self, key: tuple, index: int) -> bool:
        # A reached quota is reported once per month, not once per refused packet.
        if (key, index) in self.notices: return False
        self.notices.add((key, index))
        return True

    def tick(self):
        # Loop thread: hands the new bytes over; a new month starts from zero.
        now = self.clock()
        if now - self.last < self.interval: return
        self.last = now
        if self.pending: self.writes.put((self.period, self.pending))
        self.pending = {}
        period = current_period(now)
        if period == self.period: return
        self.period = period
        # Extras end with the month; the new one starts without them.
        self.notices.clear(), self.extras.clear()
        # Sessions keep their counters: they are emptied, not replaced.
        for counter in self.totals.values(): counter[0] = counter[1] = 0

    def write(self, period: str, pending: dict):
        for (organization_id, account_id, scope), (down, up) in pending.items():
            query = dict(organization_id=organization_id, account_id=account_id, scope=scope, period=period)
            self.collection().update_one(query, {'$inc': dict(down=down, up=up)}, upsert=True)

    def write_forever(self):
        # Writer thread: MongoDB never runs on the packet path.
        while True: self.write(*self.writes.get())

    def flush(self):
        # Writes everything now, for tests and before stopping.
        self.last = float('-inf')
        self.tick()
        while not self.writes.empty(): self.write(*self.writes.get())
