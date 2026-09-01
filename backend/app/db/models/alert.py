"""Alert and AlertHistory ORM Entities.

Alerts represent analyst-facing escalated incidents, while AlertHistory provides
an append-only lifecycle audit trail.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, GUID, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.security_event import SecurityEvent


class Alert(Base, TimestampMixin):
    """Analyst-facing escalated security incident."""

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    alert_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    disposition: Mapped[str] = mapped_column(
        String(32),
        default="OPEN",
        nullable=False,
        index=True,
    )  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE

    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    policy_version_applied: Mapped[str] = mapped_column(String(32), nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    event: Mapped[SecurityEvent] = relationship("SecurityEvent", back_populates="alert")
    history: Mapped[List[AlertHistory]] = relationship(
        "AlertHistory",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertHistory.timestamp.asc()",
    )


class AlertHistory(Base):
    """Append-only audit trail recording every state change and analyst action."""

    __tablename__ = "alert_history"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    previous_disposition: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    new_disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), default="system", nullable=False)
    action_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    alert: Mapped[Alert] = relationship("Alert", back_populates="history")


Index("ix_alerts_status_severity", Alert.disposition, Alert.severity)
