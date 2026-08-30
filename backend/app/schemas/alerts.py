"""Pydantic schemas for escalated incident alerts and audit logs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class AlertHistoryItem(BaseModel):
    """Immutable audit record entry tracking state transition."""
    id: uuid.UUID
    timestamp: datetime
    previous_disposition: Optional[str] = None
    new_disposition: str
    actor_id: str
    action_note: Optional[str] = None


class AlertSummary(BaseModel):
    """Compact summary of an incident alert for triage queues."""
    id: uuid.UUID
    event_id: uuid.UUID
    alert_type: str
    severity: str
    disposition: str
    analyst_notes: Optional[str] = None
    policy_version_applied: str
    created_at: datetime
    resolved_at: Optional[datetime] = None

    # Event context
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_name: str
    predicted_family: str
    class_confidence: float
    risk_score: int
    triage_status: str


class AlertDetail(AlertSummary):
    """Detailed view of an alert including the full append-only audit trail."""
    history: List[AlertHistoryItem]


class UpdateAlertRequest(BaseModel):
    """Request payload for updating alert workflow disposition."""
    new_disposition: str = Field(
        ...,
        description="Target disposition: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE",
    )
    actor_id: str = Field(
        default="analyst",
        description="Identifier of the analyst or automated system performing the update",
    )
    note: Optional[str] = Field(
        default=None,
        description="Mandatory or optional rationale for the triage update",
    )
