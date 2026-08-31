"""Tests for Security Hardening and Defensive Response Middleware.

Verifies:
- Security headers presence on HTTP responses (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy)
- Conditional Strict-Transport-Security (HSTS) behavior (enabled only when ENABLE_HTTPS=true)
- In-memory rate limiting enforcement and 429 Retry-After response
- Model artifact checksum validation on startup
- CORS origin string parsing
"""

import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.main import app
from app.core.config import settings
from app.core.security import InMemoryRateLimiter, parse_cors_origins
from app.services.model_registry import get_model_registry, KNOWN_MODEL_CATALOG


class TestSecurityHardening(unittest.TestCase):
    """Test suite for security headers, rate limiting, and integrity verification."""

    def setUp(self):
        self.client = TestClient(app)

    def test_security_headers_present(self):
        """HTTP responses include modern defensive security headers."""
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)

        # Check defensive MIME and Framing headers
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(
            response.headers.get("Referrer-Policy"),
            "strict-origin-when-cross-origin",
        )
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))

    def test_hsts_header_disabled_by_default(self):
        """Strict-Transport-Security is not emitted when ENABLE_HTTPS is False."""
        settings.ENABLE_HTTPS = False
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Strict-Transport-Security", response.headers)

    def test_hsts_header_emitted_when_https_enabled(self):
        """Strict-Transport-Security is emitted when ENABLE_HTTPS is True."""
        try:
            settings.ENABLE_HTTPS = True
            response = self.client.get("/health/live")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Strict-Transport-Security", response.headers)
            self.assertIn("max-age=31536000", response.headers["Strict-Transport-Security"])
        finally:
            settings.ENABLE_HTTPS = False

    def test_in_memory_rate_limiter_logic(self):
        """Rate limiter blocks subsequent calls when bucket limit is reached."""
        limiter = InMemoryRateLimiter(requests_per_minute=3, window_seconds=10.0)
        ip = "192.168.1.99"

        # First 3 requests should be allowed
        allowed1, remaining1, _ = limiter.is_allowed(ip)
        allowed2, remaining2, _ = limiter.is_allowed(ip)
        allowed3, remaining3, _ = limiter.is_allowed(ip)

        self.assertTrue(allowed1)
        self.assertTrue(allowed2)
        self.assertTrue(allowed3)
        self.assertEqual(remaining3, 0)

        # 4th request must be rejected
        allowed4, remaining4, retry_after = limiter.is_allowed(ip)
        self.assertFalse(allowed4)
        self.assertEqual(remaining4, 0)
        self.assertGreater(retry_after, 0.0)

    def test_model_registry_validates_required_checksums(self):
        """ModelRegistry verifies required models exist with matching SHA-256 hashes."""
        registry = get_model_registry()
        verified = registry.validate_required_models_exist()

        self.assertIn("protocol_a_xgboost_k48", verified)
        self.assertIn("protocol_a_isolationforest_k48", verified)
        self.assertEqual(
            verified["protocol_a_xgboost_k48"],
            KNOWN_MODEL_CATALOG["protocol_a_xgboost_k48"]["expected_sha256"],
        )

    def test_cors_origin_parser(self):
        """parse_cors_origins correctly handles comma-separated list and wildcard."""
        orig_setting = settings.CORS_ORIGINS
        try:
            settings.CORS_ORIGINS = "http://localhost:3000, http://10.0.0.1:80 "
            origins = parse_cors_origins()
            self.assertEqual(origins, ["http://localhost:3000", "http://10.0.0.1:80"])

            settings.CORS_ORIGINS = "*"
            origins = parse_cors_origins()
            self.assertEqual(origins, ["*"])
        finally:
            settings.CORS_ORIGINS = orig_setting


if __name__ == "__main__":
    unittest.main()
