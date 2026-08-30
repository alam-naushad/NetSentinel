"""Event Repository.

High-performance data access layer for SecurityEvent records with parameterized filters,
server-side pagination, and eager relation loading.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, List, Optional, Sequence, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.alert import Alert
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.model_decision import ModelDecision
from app.db.models.security_event import SecurityEvent


class EventRepository:
    """Async repository for querying and managing SecurityEvent entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, event_id: uuid.UUID | str) -> Optional[SecurityEvent]:
        """Fetch a single SecurityEvent with all joined relationships."""
        uid = uuid.UUID(str(event_id)) if isinstance(event_id, str) else event_id
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.id == uid)
            .options(
                selectinload(SecurityEvent.provenance),
                selectinload(SecurityEvent.decision),
                selectinload(SecurityEvent.alert).selectinload(Alert.history),
                selectinload(SecurityEvent.job),
            )
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def search_events(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severities: Optional[Sequence[str]] = None,
        triage_statuses: Optional[Sequence[str]] = None,
        attack_families: Optional[Sequence[str]] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        min_risk_score: Optional[int] = None,
        max_risk_score: Optional[int] = None,
        is_statistical_anomaly: Optional[bool] = None,
        job_id: Optional[uuid.UUID | str] = None,
        sort_by: str = "event_timestamp",
        sort_order: str = "desc",
    ) -> Tuple[List[SecurityEvent], int]:
        """Query security events matching multi-dimensional criteria with server-side pagination.
        
        Returns:
            (items, total_count)
        """
        page = max(1, page)
        page_size = min(max(1, page_size), 500)

        # Base query with provenance join if IP/port filtering requested
        query = select(SecurityEvent)
        count_query = select(func.count(SecurityEvent.id))

        joins_provenance = any([src_ip, dst_ip, src_port, dst_port, protocol])
        if joins_provenance:
            query = query.join(SecurityEvent.provenance)
            count_query = count_query.join(SecurityEvent.provenance)

        # Build filter predicates
        filters = []
        if start_time:
            filters.append(SecurityEvent.event_timestamp >= start_time)
        if end_time:
            filters.append(SecurityEvent.event_timestamp <= end_time)
        if severities:
            filters.append(SecurityEvent.severity.in_(severities))
        if triage_statuses:
            filters.append(SecurityEvent.triage_status.in_(triage_statuses))
        if attack_families:
            filters.append(SecurityEvent.predicted_family.in_(attack_families))
        if min_risk_score is not None:
            filters.append(SecurityEvent.risk_score >= min_risk_score)
        if max_risk_score is not None:
            filters.append(SecurityEvent.risk_score <= max_risk_score)
        if is_statistical_anomaly is not None:
            filters.append(SecurityEvent.is_statistical_anomaly == is_statistical_anomaly)
        if job_id:
            jid = uuid.UUID(str(job_id)) if isinstance(job_id, str) else job_id
            filters.append(SecurityEvent.job_id == jid)

        # Provenance filters
        if src_ip:
            if "/" in src_ip or "%" in src_ip:
                filters.append(FlowProvenance.src_ip.like(f"{src_ip.split('/')[0]}%"))
            else:
                filters.append(FlowProvenance.src_ip == src_ip)
        if dst_ip:
            if "/" in dst_ip or "%" in dst_ip:
                filters.append(FlowProvenance.dst_ip.like(f"{dst_ip.split('/')[0]}%"))
            else:
                filters.append(FlowProvenance.dst_ip == dst_ip)
        if src_port:
            filters.append(FlowProvenance.src_port == src_port)
        if dst_port:
            filters.append(FlowProvenance.dst_port == dst_port)
        if protocol:
            filters.append(FlowProvenance.protocol_name == protocol.upper())

        if filters:
            query = query.where(*filters)
            count_query = count_query.where(*filters)

        # Execute count query
        count_res = await self.session.execute(count_query)
        total_count = count_res.scalar() or 0

        # Apply sorting
        sort_col = getattr(SecurityEvent, sort_by, SecurityEvent.event_timestamp)
        if sort_order.lower() == "asc":
            query = query.order_by(sort_col.asc())
        else:
            query = query.order_by(sort_col.desc())

        # Apply pagination and eager loading
        query = (
            query.offset((page - 1) * page_size)
            .limit(page_size)
            .options(
                selectinload(SecurityEvent.provenance),
                selectinload(SecurityEvent.decision),
                selectinload(SecurityEvent.alert),
            )
        )

        res = await self.session.execute(query)
        items = list(res.scalars().all())

        return items, total_count

    async def get_summary_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """Aggregate high-level threat statistics over a time window."""
        filters = []
        if start_time:
            filters.append(SecurityEvent.event_timestamp >= start_time)
        if end_time:
            filters.append(SecurityEvent.event_timestamp <= end_time)

        # Total events
        stmt_tot = select(func.count(SecurityEvent.id))
        if filters: stmt_tot = stmt_tot.where(*filters)
        tot = (await self.session.execute(stmt_tot)).scalar() or 0

        # Anomalies flagged
        stmt_anom = select(func.count(SecurityEvent.id)).where(SecurityEvent.is_statistical_anomaly.is_(True))
        if filters: stmt_anom = stmt_anom.where(*filters)
        anom = (await self.session.execute(stmt_anom)).scalar() or 0

        # Attack family distribution
        stmt_fam = (
            select(SecurityEvent.predicted_family, func.count(SecurityEvent.id))
            .group_by(SecurityEvent.predicted_family)
        )
        if filters: stmt_fam = stmt_fam.where(*filters)
        fam_res = (await self.session.execute(stmt_fam)).all()
        attack_dist = {f: cnt for f, cnt in fam_res}

        # Severity distribution
        stmt_sev = (
            select(SecurityEvent.severity, func.count(SecurityEvent.id))
            .group_by(SecurityEvent.severity)
        )
        if filters: stmt_sev = stmt_sev.where(*filters)
        sev_res = (await self.session.execute(stmt_sev)).all()
        sev_dist = {s: cnt for s, cnt in sev_res}

        # Status distribution
        stmt_stat = (
            select(SecurityEvent.triage_status, func.count(SecurityEvent.id))
            .group_by(SecurityEvent.triage_status)
        )
        if filters: stmt_stat = stmt_stat.where(*filters)
        stat_res = (await self.session.execute(stmt_stat)).all()
        status_dist = {st: cnt for st, cnt in stat_res}

        benign_count = attack_dist.get("BENIGN", 0)
        attack_count = tot - benign_count

        return {
            "total_events": tot,
            "total_attacks": attack_count,
            "total_benign": benign_count,
            "total_anomalies": anom,
            "attack_distribution": attack_dist,
            "severity_distribution": sev_dist,
            "status_distribution": status_dist,
        }
