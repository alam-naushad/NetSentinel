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

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Callable, List
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


async def check_rate_limit(request: Request, limiter: InMemoryRateLimiter) -> Response | None:
    """Dependency helper to enforce rate limiting on specific routes."""
    if not settings.RATE_LIMIT_ENABLED:
        return None

    # Resolve client IP (respecting forward headers if behind trusted proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"

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
