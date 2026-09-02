"""Pytest test configuration and fixtures."""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.security import AuthenticatedUser, get_current_user
from app.main import app


@pytest.fixture(autouse=True)
def default_auth_for_legacy_tests(request):
    """Automatically provide an authenticated analyst session for existing functional tests.

    Tests in test_auth_api specifically test unauthenticated rejection, login, and token
    handling, so they bypass this automatic override.
    """
    if "test_auth_api" in request.node.nodeid:
        yield
        return

    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
        username="soc_analyst", role="analyst"
    )
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)
