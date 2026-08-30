"""Analysis Job ORM Entity.

Tracks PCAP upload runs and batch ingestion units.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, List
from sqlalchemy import BigInteger, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, GUID, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.security_event import SecurityEvent


class AnalysisJob(Base, TimestampMixin):
    """Represents a discrete ingestion job (e.g. PCAP file upload)."""

    __tablename__ = "analysis_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    source_type: Mapped[str] = mapped_column(
        String(32),
        default="PCAP_BATCH",
        nullable=False,
        index=True,
    )  # PCAP_BATCH, REST_EVAL, LIVE_ZEEK
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    
    total_flows_extracted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_flows_analyzed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    anomalies_flagged: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processing_time_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        default="COMPLETED",
        nullable=False,
        index=True,
    )  # COMPLETED, FAILED, PROCESSING

    # 1-to-many relationship with security events
    events: Mapped[List[SecurityEvent]] = relationship(
        "SecurityEvent",
        back_populates="job",
        cascade="all, delete-orphan",
    )
