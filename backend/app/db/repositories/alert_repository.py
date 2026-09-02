"""Alert Repository.

Manages escalated incident alerts and append-only lifecycle audit histories.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.alert import Alert, AlertHistory
from app.db.models.security_event import SecurityEvent


class AlertRepository:
    """Async repository for querying and updating escalated security alerts."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, alert_id: uuid.UUID | str) -> Optional[Alert]:
        """Fetch a single Alert with all event, provenance, and history relations."""
        uid = uuid.UUID(str(alert_id)) if isinstance(alert_id, str) else alert_id
        stmt = (
            select(Alert)
            .where(Alert.id == uid)
            .options(
                selectinload(Alert.event).selectinload(SecurityEvent.provenance),
                selectinload(Alert.event).selectinload(SecurityEvent.decision),
                selectinload(Alert.history),
            )
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def search_alerts(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        dispositions: Optional[Sequence[str]] = None,
        severities: Optional[Sequence[str]] = None,
        alert_types: Optional[Sequence[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> Tuple[List[Alert], int]:
        """Search and paginate escalated incident alerts."""
        page = max(1, page)
        page_size = min(max(1, page_size), 500)

        query = select(Alert)
        count_query = select(func.count(Alert.id))

        filters = []
        if dispositions:
            filters.append(Alert.disposition.in_(dispositions))
        if severities:
            filters.append(Alert.severity.in_(severities))
        if alert_types:
            filters.append(Alert.alert_type.in_(alert_types))
        if start_time:
            filters.append(Alert.created_at >= start_time)
        if end_time:
            filters.append(Alert.created_at <= end_time)

        if filters:
            query = query.where(*filters)
            count_query = count_query.where(*filters)

        count_res = await self.session.execute(count_query)
        total_count = count_res.scalar() or 0

        sort_col = getattr(Alert, sort_by, Alert.created_at)
        if sort_order.lower() == "asc":
            query = query.order_by(sort_col.asc())
        else:
            query = query.order_by(sort_col.desc())

        query = (
            query.offset((page - 1) * page_size)
            .limit(page_size)
            .options(
                selectinload(Alert.event).selectinload(SecurityEvent.provenance),
                selectinload(Alert.history),
            )
        )

        res = await self.session.execute(query)
        items = list(res.scalars().all())

        return items, total_count

    async def update_disposition(
        self,
        alert_id: uuid.UUID | str,
        *,
        new_disposition: str,
        actor_id: str = "analyst",
        note: Optional[str] = None,
    ) -> Optional[Alert]:
        """Atomically update alert workflow state and append to immutable AlertHistory audit log."""
        alert = await self.get_by_id(alert_id)
        if not alert:
            return None

        previous_disp = alert.disposition
        now_utc = datetime.now(timezone.utc)

        # 1. Update Alert state
        alert.disposition = new_disposition
        if note:
            alert.analyst_notes = note
        if new_disposition in ("RESOLVED", "FALSE_POSITIVE"):
            alert.resolved_at = now_utc

        # 2. Append immutable Audit History Record
        history_entry = AlertHistory(
            id=uuid.uuid4(),
            alert=alert,
            alert_id=alert.id,
            timestamp=now_utc,
            previous_disposition=previous_disp,
            new_disposition=new_disposition,
            actor_id=actor_id,
            action_note=note,
        )
        self.session.add(history_entry)

        await self.session.flush()
        await self.session.refresh(alert, ["history"])
        return alert

    async def get_alert_counts_by_disposition(self) -> dict[str, int]:
        """Get summary count of alerts broken down by disposition."""
        stmt = select(Alert.disposition, func.count(Alert.id)).group_by(Alert.disposition)
        res = (await self.session.execute(stmt)).all()
        return {disp: cnt for disp, cnt in res}
