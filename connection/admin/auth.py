import secrets
import time


class WebSession:
    def __init__(self, account_id, session_id: bytes, now: float):
        self.account_id, self.session_id = account_id, session_id
        self.created = self.last_seen = now


class WebSessions:
    # Panel logins stay in memory and die with the VPN session behind them.
    def __init__(self, idle: float = 900, lifetime: float = 28800,
                 attempts: int = 3, delay: float = 60, maximum_delay: float = 3600):
        self.idle, self.lifetime = idle, lifetime
        self.attempts, self.delay, self.maximum_delay = attempts, delay, maximum_delay
        self.sessions, self.failures, self.checking = {}, {}, set()

    def create(self, session, now: float = None) -> str:
        now = time.monotonic() if now is None else now
        token = secrets.token_urlsafe(32)
        self.sessions[token] = WebSession(session.account_id, session.cipher.session_id, now)
        self.failures.pop(session.account_id, None)
        return token

    def _expired(self, web: WebSession, now: float) -> bool:
        return now - web.last_seen > self.idle or now - web.created > self.lifetime

    def valid(self, token: str, session, touch: bool = True, now: float = None) -> bool:
        now = time.monotonic() if now is None else now
        web = self.sessions.get(token) if token and session else None
        if not web: return False
        bound = web.session_id == session.cipher.session_id
        bound = bound and web.account_id == session.account_id
        if not bound or self._expired(web, now):
            self.sessions.pop(token, None)
            return False
        if touch: web.last_seen = now
        return True

    def remove(self, token: str):
        self.sessions.pop(token, None)

    def blocked(self, account_id, now: float = None) -> float:
        now = time.monotonic() if now is None else now
        failure = self.failures.get(account_id)
        return max(0.0, failure[1] - now) if failure else 0.0

    def failed(self, account_id, now: float = None) -> float:
        # From the third failure on, every new one doubles the waiting time.
        now = time.monotonic() if now is None else now
        count = self.failures.get(account_id, (0, 0))[0] + 1
        exponent = count - self.attempts
        wait = 0 if exponent < 0 else min(self.maximum_delay, self.delay * 2 ** exponent)
        self.failures[account_id] = count, now + wait
        return wait

    def cleanup(self, now: float = None):
        now = time.monotonic() if now is None else now
        for token, web in list(self.sessions.items()):
            if self._expired(web, now): self.sessions.pop(token, None)
        # Escalation is remembered for a day after the last block ends.
        for account_id, (_, until) in list(self.failures.items()):
            if now - until > 86400: self.failures.pop(account_id, None)
