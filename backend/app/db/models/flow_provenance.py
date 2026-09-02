"""Flow Provenance ORM Entity.

Strictly separated network 5-tuple and session identity metadata.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional, Dict, Any
from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, GUID, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.security_event import SecurityEvent


class FlowProvenance(Base, TimestampMixin):
    """Network identity and capture provenance for a reconstructed flow."""

    __tablename__ = "flow_provenance"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    flow_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    ip_proto: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol_name: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False)
    total_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    zeek_uid: Mapped[Optional[str]] = mapped_column(String(24), nullable=True, index=True)
    conn_state: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    history: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    missed_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    zeek_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    event: Mapped[SecurityEvent] = relationship("SecurityEvent", back_populates="provenance")
