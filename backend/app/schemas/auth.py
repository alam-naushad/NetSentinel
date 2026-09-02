"""Pydantic schemas for Application-Level Authentication."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Payload submitted to POST /api/v1/auth/login."""
    username: str = Field(..., min_length=1, max_length=64, description="Operator username")
    password: str = Field(..., min_length=1, max_length=128, description="Operator password")


class UserResponse(BaseModel):
    """Authenticated user profile returned by /api/v1/auth/me and login."""
    username: str
    role: str = "analyst"
    authenticated: bool = True


class LogoutResponse(BaseModel):
    """Response returned when ending the active session."""
    status: str = "ok"
    message: str = "Session closed"
