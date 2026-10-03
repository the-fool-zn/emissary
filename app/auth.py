"""Password hashing, signed sessions and login rate limiting. Standard library + itsdangerous only."""
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Optional

from itsdangerous import BadSignature, URLSafeTimedSerializer

ITERATIONS = 600_000
PREFIX = "pbkdf2:sha256"
SESSION_COOKIE = "emissary_session"
LOGIN_COOKIE = "emissary_lc"


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    """PBKDF2-HMAC-SHA256. The format has no '$' characters, so it is safe inside .env and Docker."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return f"{PREFIX}:{iterations}:{salt}:{dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, hname, iters, salt, digest = stored.split(":")
        if f"{algo}:{hname}" != PREFIX:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode()[:512], bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, AttributeError):
        return False


class Sessions:
    """Stateless signed cookies. Rotating SESSION_SECRET logs everybody out."""

    def __init__(self, secret: str, max_age: int):
        self.max_age = max_age
        self._session = URLSafeTimedSerializer(secret, salt="emissary-session")
        self._login = URLSafeTimedSerializer(secret, salt="emissary-login-csrf")

    def create(self, user: str) -> tuple:
        sess = {"u": user, "csrf": secrets.token_urlsafe(24)}
        return self._session.dumps(sess), sess

    def read(self, value: Optional[str]) -> Optional[dict]:
        if not value:
            return None
        try:
            data = self._session.loads(value, max_age=self.max_age)
        except BadSignature:                        # includes expiry
            return None
        return data if isinstance(data, dict) and "u" in data and "csrf" in data else None

    def new_login_token(self) -> tuple:
        token = secrets.token_urlsafe(24)
        return token, self._login.dumps(token)

    def check_login_token(self, cookie: Optional[str], form_token: str) -> bool:
        if not cookie:
            return False
        try:
            return hmac.compare_digest(self._login.loads(cookie, max_age=600), form_token or "")
        except BadSignature:
            return False


class RateLimiter:
    def __init__(self, limit: int, window_sec: int):
        self.limit, self.window = limit, window_sec
        self._hits = defaultdict(deque)
        self._lock = Lock()

    def _purge(self, key):
        q, cutoff = self._hits[key], time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._purge(key)) >= self.limit

    def hit(self, key: str):
        with self._lock:
            self._purge(key).append(time.monotonic())

    def reset(self, key: str):
        with self._lock:
            self._hits.pop(key, None)
