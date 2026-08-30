"""Health and System Status API routes."""

from typing import Any
from fastapi import APIRouter
from app.core.database import check_database_connection

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, Any]:
    """Health check reporting API and database connectivity status."""
    db_status = await check_database_connection()
    return {
        "status": "ok",
        "service": "network-anomaly-api",
        "persistence": db_status,
    }
