"""Database Connection and Session Management.

Provides async SQLAlchemy 2.0 engine, session factories, and dependency injection.
"""

from __future__ import annotations

import logging
from typing import Any, AsyncGenerator, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

logger = logging.getLogger(__name__)

# Global engine and session factory singletons
_async_engine: AsyncEngine | None = None
_async_session_maker: async_sessionmaker[AsyncSession] | None = None


def get_async_engine() -> AsyncEngine:
    """Obtain or initialize the global AsyncEngine."""
    global _async_engine
    if _async_engine is None:
        url = settings.DATABASE_URL
        is_sqlite = url.startswith("sqlite")

        engine_kwargs: dict = {
            "echo": settings.DEBUG,
            "future": True,
        }

        if not is_sqlite:
            engine_kwargs.update({
                "pool_size": settings.DB_POOL_SIZE,
                "max_overflow": settings.DB_MAX_OVERFLOW,
                "pool_timeout": min(settings.DB_POOL_TIMEOUT, 3.0),
                "pool_pre_ping": True,
            })

        _async_engine = create_async_engine(url, **engine_kwargs)
    return _async_engine


def get_async_session_maker() -> async_sessionmaker[AsyncSession]:
    """Obtain or initialize the global async session factory."""
    global _async_session_maker
    if _async_session_maker is None:
        engine = get_async_engine()
        _async_session_maker = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _async_session_maker


async def get_db() -> AsyncGenerator[Optional[AsyncSession], None]:
    """FastAPI dependency yielding an async database session, or None if unavailable in ephemeral mode."""
    session_maker = get_async_session_maker()
    try:
        async with session_maker() as session:
            try:
                yield session
                if session.is_active:
                    try:
                        await session.commit()
                    except Exception:
                        pass
            except Exception:
                if session.is_active:
                    try:
                        await session.rollback()
                    except Exception:
                        pass
                if settings.DATABASE_REQUIRED:
                    raise
    except Exception as e:
        if settings.DATABASE_REQUIRED:
            logger.critical("Database session error with DATABASE_REQUIRED=True: %s", e)
            raise
        else:
            logger.debug("Database session error caught in get_db: %s", e)


async def check_database_connection() -> dict[str, Any]:
    """Inspect database connectivity and dialect for health checks.

    Returns:
        dict with status ('connected', 'unavailable'), dialect, and error if any.
    """
    try:
        engine = get_async_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {
            "connected": True,
            "dialect": engine.dialect.name,
            "database_url": settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else "local",
            "required": settings.DATABASE_REQUIRED,
            "mode": "persistent",
        }
    except Exception as e:
        logger.warning("Database connection check failed: %s", e)
        return {
            "connected": False,
            "dialect": None,
            "error": str(e),
            "required": settings.DATABASE_REQUIRED,
            "mode": "ephemeral" if not settings.DATABASE_REQUIRED else "failing",
        }
