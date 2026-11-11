import time

DIRECTIONS = 'down', 'up'
# Data allowed per month, in megabytes (10^6 bytes), next to the speeds.
QUOTAS = 'quota_down', 'quota_up'
FIELDS = DIRECTIONS + QUOTAS
SCOPES = 'network', 'internet'
# Kilobits per second: 1 kbps up to 10 Gbps; megabytes: 1 MB up to 1 PB.
MAXIMUM, MAXIMUM_QUOTA = 10_000_000, 1_000_000_000
MEGABYTE = 1_000_000
# A burst of half a second, never below 32 KiB, keeps short pages from stalling.
BURST, MINIMUM_BURST = 0.5, 32768


class TokenBucket:
    def __init__(self, kbps: int):
        self.kbps, self.rate = kbps, kbps * 125
        self.capacity = max(self.rate * BURST, MINIMUM_BURST)
        self.tokens, self.stamp = self.capacity, time.monotonic()

    def refill(self, now: float) -> float:
        self.tokens = min(self.capacity, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        return self.tokens


class Limiter:
    """The buckets of one session: a network limit for everything that goes
    through it, and an internet limit on top for what leaves the server.
    Monthly quotas cut the traffic once the bytes counted by Usage reach them."""

    def __init__(self, network=(None, None), internet=(None, None)):
        self.network, self.internet = {}, {}
        self.quotas = {scope: [None, None] for scope in SCOPES}
        self.usage, self.keys, self.extras, self.on_quota = None, {}, {}, None
        self.set(network, internet)

    def bind(self, usage, keys: dict, on_quota=None, extras: dict = None):
        # keys: the Usage counter of each scope this session spends from;
        # extras: the month's extra keys of each scope, its own and its role's.
        self.usage, self.keys, self.on_quota, self.extras = usage, keys, on_quota, extras or {}

    def set_quotas(self, network=None, internet=None):
        # Megabytes per month, or None for no quota.
        for scope, values in (('network', network), ('internet', internet)):
            if values is not None: self.quotas[scope] = [None if mb is None else mb * MEGABYTE for mb in values]

    def set(self, network=None, internet=None):
        # Changing a limit keeps nothing of the old bucket but its existence.
        for buckets, values in ((self.network, network), (self.internet, internet)):
            if values is None: continue
            for direction, kbps in zip(DIRECTIONS, values):
                current = buckets.get(direction)
                if kbps is None: buckets.pop(direction, None)
                elif not current or current.kbps != kbps: buckets[direction] = TokenBucket(kbps)

    def limits(self) -> dict:
        def kbps(buckets): return tuple(buckets[d].kbps if d in buckets else None for d in DIRECTIONS)
        return dict(network=kbps(self.network), internet=kbps(self.internet))

    def allow(self, direction: str, size: int, internet: bool = False) -> bool:
        # A spent quota cuts first; then the speed buckets; only allowed bytes are counted.
        index, scopes = DIRECTIONS.index(direction), SCOPES if internet else SCOPES[:1]
        for scope in scopes:
            limit, key = self.quotas[scope][index], self.keys.get(scope)
            if limit is None or not key: continue
            limit += sum(self.usage.extra(extra, index) for extra in self.extras.get(scope, ()))
            if self.usage.spent(key)[index] + size > limit:
                if self.on_quota and self.usage.first_notice(key, index): self.on_quota(scope, direction)
                return False
        if not self.within_speed(direction, size, internet): return False
        for scope in scopes:
            if self.keys.get(scope): self.usage.add(self.keys[scope], index, size)
        return True

    def within_speed(self, direction: str, size: int, internet: bool) -> bool:
        # An internet packet needs room in both buckets; a refused one spends none.
        buckets = [self.network.get(direction)]
        if internet: buckets.append(self.internet.get(direction))
        buckets = [bucket for bucket in buckets if bucket]
        if not buckets: return True
        now = time.monotonic()
        if any(bucket.refill(now) < size for bucket in buckets): return False
        for bucket in buckets: bucket.tokens -= size
        return True


def validate(limits) -> dict:
    """{roles: {id: {down, up, quota_down, quota_up}}, members: {...}}: kbps and MB, or None.

    A member entry with no values still means something: no limit for that
    person even if the role has one. An empty role entry is dropped.
    """
    if limits is None: return dict(roles={}, members={})
    if type(limits) is not dict or set(limits) - {'roles', 'members'}: raise ValueError('invalid_limits')
    result = {}
    for group in ('roles', 'members'):
        entries = limits.get(group, {})
        if type(entries) is not dict: raise ValueError('invalid_limits')
        result[group] = {}
        for owner, values in entries.items():
            if type(owner) is not str or type(values) is not dict or set(values) - set(FIELDS):
                raise ValueError('invalid_limits')
            entry = {}
            for field in FIELDS:
                value, maximum = values.get(field), MAXIMUM_QUOTA if field in QUOTAS else MAXIMUM
                if value is not None and (type(value) is not int or not 0 < value <= maximum):
                    raise ValueError('invalid_limits')
                entry[field] = value
            if group == 'roles' and entry == dict.fromkeys(FIELDS): continue
            result[group][owner] = entry
    return result


def resolve(limits: dict, role_id, account_id, fields=DIRECTIONS) -> tuple:
    # Field by field: the person's own limit, else the role's, else none.
    limits = limits or {}
    member = (limits.get('members') or {}).get(account_id.__str__())
    role = (limits.get('roles') or {}).get(role_id.__str__()) if role_id else None
    result = []
    for field in fields:
        if member is not None and field in member: result.append(member[field])
        else: result.append((role or {}).get(field))
    return tuple(result)
