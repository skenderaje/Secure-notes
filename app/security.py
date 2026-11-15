"""Password hashing, CSRF tokens, login throttling and security headers."""

import hmac
import re
import secrets
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings

# ── Passwords ─────────────────────────────────────────────────

_hasher = PasswordHasher()
# Verified when the username does not exist, so a miss costs as much time as a wrong password.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN, PASSWORD_MAX = 12, 128


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def validate_credentials(username: str, password: str) -> str | None:
    """Return an error message, or None when the pair is acceptable for sign-up."""
    if not USERNAME_RE.fullmatch(username):
        return "Username: 3-32 characters, letters, digits and underscore only."
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        return f"Password: between {PASSWORD_MIN} and {PASSWORD_MAX} characters."
    if password.lower() == username.lower():
        return "Password must differ from the username."
    return None


# ── CSRF ──────────────────────────────────────────────────────


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def check_csrf(request: Request, submitted: str) -> None:
    expected = request.session.get("csrf")
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


# ── Login throttling ──────────────────────────────────────────


class LoginThrottle:
    """At most `limit` failed logins per key in `window` seconds. In-memory, per process."""

    def __init__(self, limit: int = 5, window: int = 15 * 60) -> None:
        self.limit, self.window = limit, window
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._prune(key, time.monotonic())) >= self.limit

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


login_throttle = LoginThrottle()


# ── Security headers ──────────────────────────────────────────

_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for name, value in _HEADERS.items():
            response.headers.setdefault(name, value)
        if settings.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path not in ("/healthz",) and not request.url.path.startswith("/static"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
