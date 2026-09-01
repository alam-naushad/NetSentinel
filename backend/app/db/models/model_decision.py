"""Model Decision Audit ORM Entity.

Tracks the exact model version, raw scores, calibrated thresholds, and policy explanation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, GUID, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.security_event import SecurityEvent


class ModelDecision(Base, TimestampMixin):
    """Immutable audit record linking an event to its evaluation metadata."""

    __tablename__ = "model_decisions"

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

    supervised_model_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    anomaly_model_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_decision_score: Mapped[float] = mapped_column(Float, nullable=False)
    calibrated_threshold: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    event: Mapped[SecurityEvent] = relationship("SecurityEvent", back_populates="decision")
