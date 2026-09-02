"""Escalated Incident Alerts and Analyst Triage API routes."""

from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthenticatedUser, get_current_user
from app.db.repositories.alert_repository import AlertRepository
from app.schemas.alerts import (
    AlertDetail,
    AlertHistoryItem,
    AlertSummary,
    UpdateAlertRequest,
)
from app.schemas.telemetry import PageResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_DISPOSITIONS = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


@router.get("", response_model=PageResponse[AlertSummary])
async def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    disposition: Optional[List[str]] = Query(default=None, description="Filter by disposition"),
    severity: Optional[List[str]] = Query(default=None, description="Filter by severity"),
    alert_type: Optional[List[str]] = Query(default=None, description="Filter by alert type"),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="desc"),
    db: Optional[AsyncSession] = Depends(get_db),
) -> PageResponse[AlertSummary]:
    """Retrieve paginated active and historical security alerts for the SOC triage queue."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    repo = AlertRepository(db)
    items, total = await repo.search_alerts(
        page=page,
        page_size=page_size,
        dispositions=disposition,
        severities=severity,
        alert_types=alert_type,
        start_time=start_time,
        end_time=end_time,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    summaries: List[AlertSummary] = []
    for al in items:
        ev = al.event
        prov = ev.provenance if ev else None
        summaries.append(
            AlertSummary(
                id=al.id,
                event_id=al.event_id,
                alert_type=al.alert_type,
                severity=al.severity,
                disposition=al.disposition,
                analyst_notes=al.analyst_notes,
                policy_version_applied=al.policy_version_applied,
                created_at=al.created_at,
                resolved_at=al.resolved_at,
                src_ip=prov.src_ip if prov else "—",
                dst_ip=prov.dst_ip if prov else "—",
                src_port=prov.src_port if prov else 0,
                dst_port=prov.dst_port if prov else 0,
                protocol_name=prov.protocol_name if prov else "—",
                predicted_family=ev.predicted_family if ev else "—",
                class_confidence=ev.class_confidence if ev else 0.0,
                risk_score=ev.risk_score if ev else 0,
                triage_status=ev.triage_status if ev else "—",
            )
        )

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return PageResponse(
        items=summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert_detail(
    alert_id: uuid.UUID,
    db: Optional[AsyncSession] = Depends(get_db),
) -> AlertDetail:
    """Retrieve full alert details including the complete append-only audit trail."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    repo = AlertRepository(db)
    al = await repo.get_by_id(alert_id)
    if not al:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' was not found.",
        )

    ev = al.event
    prov = ev.provenance if ev else None

    history_items = [
        AlertHistoryItem(
            id=h.id or uuid.uuid4(),
            timestamp=h.timestamp,
            previous_disposition=h.previous_disposition,
            new_disposition=h.new_disposition,
            actor_id=h.actor_id,
            action_note=h.action_note,
        )
        for h in al.history
    ]

    return AlertDetail(
        id=al.id,
        event_id=al.event_id,
        alert_type=al.alert_type,
        severity=al.severity,
        disposition=al.disposition,
        analyst_notes=al.analyst_notes,
        policy_version_applied=al.policy_version_applied,
        created_at=al.created_at,
        resolved_at=al.resolved_at,
        src_ip=prov.src_ip if prov else "—",
        dst_ip=prov.dst_ip if prov else "—",
        src_port=prov.src_port if prov else 0,
        dst_port=prov.dst_port if prov else 0,
        protocol_name=prov.protocol_name if prov else "—",
        predicted_family=ev.predicted_family if ev else "—",
        class_confidence=ev.class_confidence if ev else 0.0,
        risk_score=ev.risk_score if ev else 0,
        triage_status=ev.triage_status if ev else "—",
        history=history_items,
    )


@router.patch("/{alert_id}", response_model=AlertDetail)
async def update_alert_disposition(
    alert_id: uuid.UUID,
    payload: UpdateAlertRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Optional[AsyncSession] = Depends(get_db),
) -> AlertDetail:
    """Update alert disposition and atomically append an immutable audit record."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    new_disp = payload.new_disposition.strip().upper()
    if new_disp not in VALID_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid disposition '{payload.new_disposition}'. Allowed: {sorted(VALID_DISPOSITIONS)}",
        )

    # Security requirement: actor_id is strictly derived from the authenticated server identity.
    # Any client-supplied payload.actor_id is completely ignored for audit integrity.
    server_actor_id = current_user.username

    repo = AlertRepository(db)
    updated_alert = await repo.update_disposition(
        alert_id=alert_id,
        new_disposition=new_disp,
        actor_id=server_actor_id,
        note=payload.note,
    )

    if not updated_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' was not found.",
        )

    return await get_alert_detail(alert_id, db)
