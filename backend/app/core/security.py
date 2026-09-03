"""Security Middleware and Rate Limiting for Hardened Capstone Deployment.

Provides:
- SecurityHeadersMiddleware: Sets defensive HTTP response headers (X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Content-Security-Policy, and conditional HSTS).
- InMemoryRateLimiter: Process-local sliding-window rate limiter for resource-intensive
  inference and upload endpoints.

Documented Invariants:
- Rate limits are process-local, held in memory, and reset upon process restart.
- Strict-Transport-Security (HSTS) is ONLY emitted when ENABLE_HTTPS=true.
- Legacy X-XSS-Protection is omitted in favor of modern Content-Security-Policy.
"""

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict
from typing import Callable, List, Optional
from fastapi import HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from app.core.config import settings

logger = logging.getLogger(__name__)


def parse_cors_origins() -> List[str]:
    """Parse CORS_ORIGINS setting into a list of allowed origin strings."""
    raw = settings.CORS_ORIGINS.strip()
    if raw == "*":
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies modern security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Defensive MIME and Framing headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy (allows self-hosted scripts, styles, and SSE/WS connections)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self';"
        )

        # Strict-Transport-Security ONLY when HTTPS is explicitly enabled
        if settings.ENABLE_HTTPS:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


class InMemoryRateLimiter:
    """Sliding-window process-local in-memory rate limiter.

    Note:
        Rate limit buckets are stored in-memory per client IP and reset upon
        application restart. Multi-node distributed enforcement is intentionally
        out of scope for this single-node capstone system.
    """

    def __init__(self, requests_per_minute: int = 60, window_seconds: float = 60.0):
        self.limit = requests_per_minute
        self.window = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> tuple[bool, int, float]:
        """Check if request from client_ip is permitted.

        Returns:
            (allowed: bool, remaining_requests: int, retry_after_seconds: float)
        """
        now = time.monotonic()
        cutoff = now - self.window
        timestamps = self._history[client_ip]

        # Evict timestamps older than sliding window
        valid_timestamps = [t for t in timestamps if t > cutoff]
        self._history[client_ip] = valid_timestamps

        if len(valid_timestamps) >= self.limit:
            oldest = valid_timestamps[0]
            retry_after = max(0.1, round((oldest + self.window) - now, 1))
            return False, 0, retry_after

        valid_timestamps.append(now)
        remaining = self.limit - len(valid_timestamps)
        return True, remaining, 0.0


# Singleton rate limiters for specific route groups
inference_rate_limiter = InMemoryRateLimiter(
    requests_per_minute=settings.RATE_LIMIT_INFERENCE_PER_MIN,
    window_seconds=60.0,
)

upload_rate_limiter = InMemoryRateLimiter(
    requests_per_minute=settings.RATE_LIMIT_UPLOAD_PER_MIN,
    window_seconds=60.0,
)


def resolve_client_ip(request: Request) -> str:
    """Accurately determine client IP from reverse proxy configuration.

    In our deployment, Nginx explicitly overwrites 'X-Real-IP' with $remote_addr,
    preventing client-supplied spoofing of upstream proxy hops.
    """
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


login_rate_limiter = InMemoryRateLimiter(
    requests_per_minute=settings.AUTH_LOGIN_RATE_LIMIT_PER_MIN,
    window_seconds=60.0,
)


async def check_rate_limit(request: Request, limiter: InMemoryRateLimiter) -> Response | None:
    """Dependency helper to enforce rate limiting on specific routes."""
    if not settings.RATE_LIMIT_ENABLED:
        return None

    client_ip = resolve_client_ip(request)
    allowed, remaining, retry_after = limiter.is_allowed(client_ip)
    if not allowed:
        logger.warning(
            "Rate limit exceeded for client IP %s (retry after %.1fs)",
            client_ip, retry_after,
        )
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded. Try again in {retry_after} seconds.",
                "retry_after": retry_after,
            },
            headers={"Retry-After": str(int(retry_after))},
        )
    return None


# ==============================================================================
# Authentication & Session Security (PBKDF2 + Stateless Signed HttpOnly Cookie)
# ==============================================================================

@dataclass(frozen=True)
class AuthenticatedUser:
    """Authenticated principal representing an active operator."""
    username: str
    role: str = "analyst"


# NIST SP 800-63B compliant PBKDF2 iteration count
PBKDF2_ITERATIONS = 600_000

# Precomputed dummy hash for constant-time mitigation against user enumeration
DUMMY_PBKDF2_HASH = (
    "pbkdf2:sha256:600000$0123456789abcdef0123456789abcdef$"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def hash_password(plain_password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Securely hash a password using PBKDF2-HMAC-SHA256 with a unique cryptographic salt."""
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${derived.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Constant-time verification of a password against PBKDF2-HMAC-SHA256 hash."""
    try:
        clean_hash = password_hash.replace("$$", "$")
        parts = clean_hash.split("$")
        if len(parts) != 3:
            return False
        meta, salt_hex, hash_hex = parts
        algorithm, sub_algo, iterations_str = meta.split(":")
        if algorithm != "pbkdf2" or sub_algo != "sha256":
            return False
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        derived = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


def get_auth_secret_key() -> str:
    """Retrieve active signing key. Fails closed in production if missing."""
    if settings.AUTH_SECRET_KEY and settings.AUTH_SECRET_KEY.strip():
        return settings.AUTH_SECRET_KEY.strip()
    if settings.ENVIRONMENT == "production":
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY must be configured in production environment."
        )
    return "dev-insecure-test-secret-key-at-least-32-bytes-long!!"


def get_configured_users() -> dict[str, str]:
    """Retrieve mapping of username to PBKDF2 password hash.

    Production credentials must be supplied via AUTH_USERNAME & AUTH_PASSWORD_HASH
    or AUTH_USERS_JSON. Automatically normalizes Docker Compose '$$' escape sequences.
    """
    users: dict[str, str] = {}
    if settings.AUTH_USERS_JSON:
        try:
            parsed = json.loads(settings.AUTH_USERS_JSON)
            if isinstance(parsed, dict):
                users.update({
                    str(k).strip(): str(v).strip().replace("$$", "$")
                    for k, v in parsed.items()
                    if isinstance(k, str) and isinstance(v, str)
                })
        except Exception as e:
            logger.error("Failed to parse AUTH_USERS_JSON: %s", e)

    if settings.AUTH_USERNAME and settings.AUTH_PASSWORD_HASH:
        users[settings.AUTH_USERNAME.strip()] = settings.AUTH_PASSWORD_HASH.strip().replace("$$", "$")

    return users


def validate_auth_configuration() -> None:
    """Fail-closed validation executed during application startup.

    Enforces:
    1. AUTH_SECRET_KEY is non-empty and >= 32 characters in production.
    2. At least one production user with a valid PBKDF2 hash is configured.
    3. Prevents known development/predictable fallback keys in production.
    """
    if settings.ENVIRONMENT == "production":
        secret = (settings.AUTH_SECRET_KEY or "").strip()
        if not secret or len(secret) < 32:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY is required in production "
                "and must be at least 32 characters long. Set AUTH_SECRET_KEY in your .env file."
            )
        weak_secrets = {"secret", "changeme", "dev-insecure-test-secret-key-at-least-32-bytes-long!!"}
        if secret in weak_secrets:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY cannot use a known development secret in production."
            )
        users = get_configured_users()
        if not users:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: No production credentials configured! "
                "Please configure AUTH_USERNAME and AUTH_PASSWORD_HASH, or AUTH_USERS_JSON in .env."
            )
        for u, h in users.items():
            clean_h = h.replace("$$", "$")
            if not clean_h.startswith("pbkdf2:sha256:"):
                raise RuntimeError(
                    f"CRITICAL SECURITY CONFIGURATION ERROR: Password hash for user '{u}' "
                    "must be a valid PBKDF2-HMAC-SHA256 hash (pbkdf2:sha256:...)."
                )
            parts = clean_h.split("$")
            if len(parts) != 3:
                raise RuntimeError(
                    f"CRITICAL SECURITY CONFIGURATION ERROR: Password hash for user '{u}' "
                    "is malformed (expected 3 parts separated by $: meta$salt$hash)."
                )


def authenticate_user(username: str, password: str) -> AuthenticatedUser | None:
    """Authenticate user with constant-time verification preventing user enumeration."""
    users = get_configured_users()
    clean_username = username.strip()
    stored_hash = users.get(clean_username)

    if stored_hash is not None:
        if verify_password(password, stored_hash):
            return AuthenticatedUser(username=clean_username, role="analyst")
        return None
    else:
        # Perform constant-time dummy verification to resist timing-based enumeration
        verify_password(password, DUMMY_PBKDF2_HASH)
        return None


def create_session_token(
    username: str,
    role: str = "analyst",
    expire_minutes: int | None = None,
) -> str:
    """Create a stateless cryptographic session token (HMAC-SHA256 signed)."""
    secret = get_auth_secret_key()
    ttl = expire_minutes or settings.AUTH_TOKEN_EXPIRE_MINUTES
    now = int(time.time())
    exp = now + (ttl * 60)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": exp,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    signature = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def verify_session_token(token: str) -> AuthenticatedUser | None:
    """Verify cryptographic signature and expiry of a session token."""
    if not token or "." not in token:
        return None
    try:
        secret = get_auth_secret_key()
        payload_b64, signature = token.split(".", 1)
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None

        # Restore base64 padding
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding

        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)

        now = int(time.time())
        if payload.get("exp", 0) < now:
            return None

        username = payload.get("sub")
        role = payload.get("role", "analyst")
        if not username:
            return None

        return AuthenticatedUser(username=username, role=role)
    except Exception:
        return None


async def get_current_user(request: Request) -> AuthenticatedUser:
    """FastAPI dependency enforcing presence of a valid session cookie."""
    token = request.cookies.get(settings.AUTH_SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    user = verify_session_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired",
        )
    return user
