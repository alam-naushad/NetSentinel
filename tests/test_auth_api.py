"""Comprehensive tests for Application-Level Authentication, Session Tokens, and API Guarding."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
import sys
import time
import pytest
from fastapi.testclient import TestClient

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.config import settings
from app.core.security import (
    AuthenticatedUser,
    create_session_token,
    get_auth_secret_key,
    hash_password,
    login_rate_limiter,
    validate_auth_configuration,
    verify_password,
    verify_session_token,
)
from app.main import app


@pytest.fixture
def auth_client():
    """Test client with runtime-generated credentials (zero hardcoded plaintext passwords)."""
    dynamic_username = f"analyst_{secrets.token_hex(4)}"
    dynamic_password = secrets.token_urlsafe(24)
    hashed = hash_password(dynamic_password)

    # Configure runtime settings
    orig_user = settings.AUTH_USERNAME
    orig_hash = settings.AUTH_PASSWORD_HASH
    orig_key = settings.AUTH_SECRET_KEY
    orig_rate = settings.AUTH_LOGIN_RATE_LIMIT_PER_MIN

    settings.AUTH_USERNAME = dynamic_username
    settings.AUTH_PASSWORD_HASH = hashed
    settings.AUTH_SECRET_KEY = secrets.token_hex(32)
    settings.AUTH_LOGIN_RATE_LIMIT_PER_MIN = 5

    # Reset rate limiter history for clean test run
    login_rate_limiter._history.clear()

    client = TestClient(app)

    yield {
        "client": client,
        "username": dynamic_username,
        "password": dynamic_password,
        "password_hash": hashed,
    }

    # Teardown
    settings.AUTH_USERNAME = orig_user
    settings.AUTH_PASSWORD_HASH = orig_hash
    settings.AUTH_SECRET_KEY = orig_key
    settings.AUTH_LOGIN_RATE_LIMIT_PER_MIN = orig_rate
    login_rate_limiter._history.clear()


class TestAuthenticationMechanisms:
    """Unit and integration tests for password hashing, session tokens, and endpoints."""

    def test_pbkdf2_password_hashing_and_constant_time_verification(self):
        """Test PBKDF2 hash generation and verification with unique salts."""
        raw_pw = secrets.token_urlsafe(20)
        h1 = hash_password(raw_pw)
        h2 = hash_password(raw_pw)

        # Unique salt ensures two hashes of identical password are distinct
        assert h1 != h2
        assert h1.startswith("pbkdf2:sha256:600000$")
        assert h2.startswith("pbkdf2:sha256:600000$")

        # Constant-time verification
        assert verify_password(raw_pw, h1) is True
        assert verify_password(raw_pw, h2) is True
        assert verify_password(raw_pw + "wrong", h1) is False

        # Docker Compose $$ escaping normalization verification
        h1_escaped = h1.replace("$", "$$")
        assert verify_password(raw_pw, h1_escaped) is True

        # Malformed hash handling
        assert verify_password(raw_pw, "invalid_hash_string") is False
        assert verify_password(raw_pw, "pbkdf2:sha256:600000$onlytwoparts") is False

    def test_login_success_sets_httponly_cookie(self, auth_client):
        """Test successful login yields HTTP 200 and sets HttpOnly cookie."""
        client = auth_client["client"]
        username = auth_client["username"]
        password = auth_client["password"]

        resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == username
        assert data["role"] == "analyst"
        assert data["authenticated"] is True

        # Verify cookie attributes
        cookie_header = resp.headers.get("set-cookie", "")
        assert "httponly" in cookie_header.lower()
        assert "samesite=lax" in cookie_header.lower()
        assert "path=/" in cookie_header.lower()

    def test_login_incorrect_password_returns_generic_401(self, auth_client):
        """Test wrong password returns generic 401 without revealing password specifics."""
        client = auth_client["client"]
        username = auth_client["username"]
        bad_pw = secrets.token_urlsafe(16)

        resp = client.post("/api/v1/auth/login", json={"username": username, "password": bad_pw})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"
        assert settings.AUTH_SESSION_COOKIE_NAME not in client.cookies

    def test_login_unknown_username_returns_identical_generic_401(self, auth_client):
        """Test unknown username returns the identical generic 401 to prevent user enumeration."""
        client = auth_client["client"]
        unknown_user = f"nonexistent_{secrets.token_hex(4)}"
        any_pw = secrets.token_urlsafe(16)

        resp = client.post("/api/v1/auth/login", json={"username": unknown_user, "password": any_pw})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"

    def test_login_rate_limiting_triggers_429(self, auth_client):
        """Test repeated failed login attempts trigger HTTP 429 Too Many Requests."""
        client = auth_client["client"]
        username = auth_client["username"]
        bad_pw = secrets.token_urlsafe(12)

        # Rate limit is set to 5 per minute
        for _ in range(5):
            r = client.post("/api/v1/auth/login", json={"username": username, "password": bad_pw})
            assert r.status_code == 401

        # 6th attempt should be blocked with 429
        r_blocked = client.post("/api/v1/auth/login", json={"username": username, "password": bad_pw})
        assert r_blocked.status_code == 429
        assert "Rate limit exceeded" in r_blocked.json()["detail"]
        assert "Retry-After" in r_blocked.headers

    def test_session_token_tampering_rejected(self, auth_client):
        """Test that modifying a signed session token results in rejection."""
        token = create_session_token("analyst_1", "analyst")
        parts = token.split(".")
        # Tamper payload
        tampered_token = f"{parts[0]}xyz.{parts[1]}"
        assert verify_session_token(tampered_token) is None

        # Tamper signature
        bad_sig_token = f"{parts[0]}.{'0' * len(parts[1])}"
        assert verify_session_token(bad_sig_token) is None

    def test_expired_session_token_rejected(self, auth_client):
        """Test that an expired session token is rejected."""
        # Create token that expired 10 minutes ago
        secret = get_auth_secret_key()
        now = int(time.time())
        expired_payload = {
            "sub": "analyst_1",
            "role": "analyst",
            "iat": now - 3600,
            "exp": now - 600,
        }
        raw_json = json.dumps(expired_payload, separators=(",", ":"), sort_keys=True)
        b64 = base64.urlsafe_b64encode(raw_json.encode()).decode().rstrip("=")
        import hmac
        import hashlib
        sig = hmac.new(secret.encode(), b64.encode(), hashlib.sha256).hexdigest()
        expired_token = f"{b64}.{sig}"

        assert verify_session_token(expired_token) is None

    def test_auth_me_returns_profile_with_valid_session(self, auth_client):
        """Test GET /api/v1/auth/me returns active user profile when cookie is present."""
        client = auth_client["client"]
        username = auth_client["username"]
        password = auth_client["password"]

        # Login first
        login_res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert login_res.status_code == 200

        # Query /me
        me_res = client.get("/api/v1/auth/me")
        assert me_res.status_code == 200
        data = me_res.json()
        assert data["username"] == username
        assert data["role"] == "analyst"
        assert data["authenticated"] is True

    def test_logout_clears_cookie(self, auth_client):
        """Test POST /api/v1/auth/logout clears session cookie."""
        client = auth_client["client"]
        username = auth_client["username"]
        password = auth_client["password"]

        client.post("/api/v1/auth/login", json={"username": username, "password": password})
        logout_res = client.post("/api/v1/auth/logout")
        assert logout_res.status_code == 200
        assert logout_res.json()["status"] == "ok"

        # After logout, accessing /me should fail with 401
        me_res = client.get("/api/v1/auth/me")
        assert me_res.status_code == 401


class TestApiGuardingAndActorIntegrity:
    """Tests verifying that application routes are protected and audit trails cannot be spoofed."""

    def test_health_endpoints_remain_public_without_session(self, auth_client):
        """Verify that system health check endpoints do not require authentication."""
        client = auth_client["client"]
        # Explicitly ensure no cookies
        client.cookies.clear()

        r_root = client.get("/health")
        assert r_root.status_code in {200, 503}

        r_live = client.get("/health/live")
        assert r_live.status_code == 200

        r_api_live = client.get("/api/v1/health/live")
        assert r_api_live.status_code == 200

    def test_unauthenticated_requests_rejected_on_protected_routes(self, auth_client):
        """Verify all protected application routes return 401 without active session."""
        client = auth_client["client"]
        client.cookies.clear()

        # Models catalog
        assert client.get("/api/v1/models").status_code == 401

        # Alerts list
        assert client.get("/api/v1/alerts").status_code == 401

        # Telemetry events
        assert client.get("/api/v1/telemetry/events").status_code == 401

        # Predict flow
        dummy_flow = {"features": {f"feature_{i}": 0.0 for i in range(48)}}
        assert client.post("/api/v1/predict/flow", json=dummy_flow).status_code == 401

    def test_authenticated_requests_succeed_on_protected_routes(self, auth_client):
        """Verify protected application routes succeed when authenticated."""
        client = auth_client["client"]
        username = auth_client["username"]
        password = auth_client["password"]

        client.post("/api/v1/auth/login", json={"username": username, "password": password})

        # Models catalog should now succeed
        r_models = client.get("/api/v1/models")
        assert r_models.status_code == 200


class TestProductionFailClosed:
    """Tests verifying fail-closed invariants in production configuration."""

    def test_production_fails_closed_missing_secret_key(self, monkeypatch):
        """Production startup must raise RuntimeError if AUTH_SECRET_KEY is missing."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "AUTH_SECRET_KEY", None)
        monkeypatch.setattr(settings, "AUTH_USERNAME", "analyst")
        monkeypatch.setattr(settings, "AUTH_PASSWORD_HASH", hash_password("some_random_pw"))

        with pytest.raises(RuntimeError, match="AUTH_SECRET_KEY is required in production"):
            validate_auth_configuration()

    def test_production_fails_closed_missing_credentials(self, monkeypatch):
        """Production startup must raise RuntimeError if no users are configured."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "AUTH_SECRET_KEY", secrets.token_hex(32))
        monkeypatch.setattr(settings, "AUTH_USERNAME", None)
        monkeypatch.setattr(settings, "AUTH_PASSWORD_HASH", None)
        monkeypatch.setattr(settings, "AUTH_USERS_JSON", None)

        with pytest.raises(RuntimeError, match="No production credentials configured"):
            validate_auth_configuration()

    def test_production_fails_closed_on_weak_dev_secret(self, monkeypatch):
        """Production startup must raise RuntimeError if a known weak/dev secret is used."""
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(settings, "AUTH_SECRET_KEY", "changeme")
        monkeypatch.setattr(settings, "AUTH_USERNAME", "analyst")
        monkeypatch.setattr(settings, "AUTH_PASSWORD_HASH", hash_password("valid_hash_123"))

        with pytest.raises(RuntimeError, match="AUTH_SECRET_KEY"):
            validate_auth_configuration()
