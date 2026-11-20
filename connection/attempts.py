import time


class Attempts:
    """Failed logins and registrations, by name or by address.

    Failures wait longer each time after a few free ones; registrations are
    counted in a window. Entries that stopped mattering are dropped, and the
    table never grows past its limit: a public server faces anyone.
    """

    def __init__(self, free: int = 5, delay: float = 2, maximum_delay: float = 900,
                 registrations: int = 5, window: float = 3600, limit: int = 100_000):
        self.free, self.delay, self.maximum_delay = free, delay, maximum_delay
        self.registrations, self.window, self.limit = registrations, window, limit
        self.failures, self.created = {}, {}

    def blocked(self, keys, now: float = None) -> float:
        # Seconds left before any of these keys may try again.
        now = time.monotonic() if now is None else now
        waits = [self.failures[key][1] - now for key in keys if key in self.failures]
        return max([0] + waits)

    def failed(self, keys, now: float = None):
        now = time.monotonic() if now is None else now
        for key in keys:
            if key not in self.failures and len(self.failures) >= self.limit:
                self.cleanup(now)
                # Still full: the oldest entry makes room.
                if len(self.failures) >= self.limit:
                    del self.failures[min(self.failures, key=lambda item: self.failures[item][2])]
            count = self.failures.get(key, (0, 0))[0] + 1
            exponent = count - self.free
            wait = 0 if exponent < 0 else min(self.maximum_delay, self.delay * 2 ** exponent)
            self.failures[key] = count, now + wait, now

    def succeeded(self, keys):
        for key in keys: self.failures.pop(key, None)

    def may_register(self, address, now: float = None) -> bool:
        # A few new accounts per address and hour.
        now = time.monotonic() if now is None else now
        times = [moment for moment in self.created.get(address, ()) if now - moment < self.window]
        if len(times) >= self.registrations: return False
        if address not in self.created and len(self.created) >= self.limit:
            self.cleanup(now)
            # Still full: nobody new registers until the hour frees room.
            if len(self.created) >= self.limit: return False
        self.created[address] = times + [now]
        return True

    def cleanup(self, now: float = None):
        now = time.monotonic() if now is None else now
        for key, (_, until, last) in list(self.failures.items()):
            if until <= now and now - last > self.window: del self.failures[key]
        for address, times in list(self.created.items()):
            if all(now - moment >= self.window for moment in times): del self.created[address]
