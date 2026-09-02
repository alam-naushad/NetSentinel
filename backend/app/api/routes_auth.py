"""Application Authentication API routes.

Provides:
- POST /api/v1/auth/login  — Authenticate operator, set HttpOnly signed session cookie
- POST /api/v1/auth/logout — Clear session cookie
- GET  /api/v1/auth/me     — Return current authenticated operator profile
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.core.config import settings
from app.core.security import (
    AuthenticatedUser,
    authenticate_user,
    check_rate_limit,
    create_session_token,
    get_current_user,
    login_rate_limiter,
)
from app.schemas.auth import LoginRequest, LogoutResponse, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=UserResponse,
    summary="Authenticate operator and establish HttpOnly session",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
) -> UserResponse:
    """Validate operator credentials, apply brute-force throttling, and issue signed session cookie."""
    # 1. Enforce brute-force throttling on client IP
    rate_limit_resp = await check_rate_limit(request, login_rate_limiter)
    if rate_limit_resp is not None:
        return rate_limit_resp

    # 2. Authenticate user in constant-time (prevents user enumeration)
    user = authenticate_user(payload.username, payload.password)
    if not user:
        logger.warning("Failed login attempt for username '%s'", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # 3. Create signed stateless session token
    token = create_session_token(
        username=user.username,
        role=user.role,
        expire_minutes=settings.AUTH_TOKEN_EXPIRE_MINUTES,
    )

    # 4. Attach HttpOnly session cookie
    max_age = settings.AUTH_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        key=settings.AUTH_SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        expires=max_age,
        httponly=True,
        samesite="lax",
        path="/",
        secure=settings.ENABLE_HTTPS,
    )

    logger.info("Operator '%s' authenticated successfully. Session cookie issued.", user.username)
    return UserResponse(username=user.username, role=user.role)


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="End active session and clear cookie",
)
async def logout(response: Response) -> LogoutResponse:
    """Clear session cookie in client browser.

    Note on stateless tokens:
    The stateless HMAC session token cannot individually revoke an already-copied token
    before its cryptographic expiry. Deleting the cookie terminates the browser session.
    """
    response.delete_cookie(
        key=settings.AUTH_SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.ENABLE_HTTPS,
    )
    return LogoutResponse(status="ok", message="Session closed")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Retrieve profile of the currently authenticated operator",
)
async def get_me(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> UserResponse:
    """Return profile for active session."""
    return UserResponse(username=current_user.username, role=current_user.role)
