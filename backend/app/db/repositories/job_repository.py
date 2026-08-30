"""Job Repository.

Manages AnalysisJob records for batch uploads and live ingestion feeds.
"""

from __future__ import annotations

import uuid
from typing import List, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.analysis_job import AnalysisJob


class JobRepository:
    """Async repository for querying and creating AnalysisJob records."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, job_id: uuid.UUID | str) -> Optional[AnalysisJob]:
        """Fetch an AnalysisJob by ID."""
        uid = uuid.UUID(str(job_id)) if isinstance(job_id, str) else job_id
        stmt = select(AnalysisJob).where(AnalysisJob.id == uid)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_jobs(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[AnalysisJob], int]:
        """List historical analysis jobs with pagination."""
        page = max(1, page)
        page_size = min(max(1, page_size), 100)

        query = select(AnalysisJob).order_by(AnalysisJob.created_at.desc())
        count_query = select(func.count(AnalysisJob.id))

        count_res = await self.session.execute(count_query)
        total_count = count_res.scalar() or 0

        query = query.offset((page - 1) * page_size).limit(page_size)
        res = await self.session.execute(query)
        items = list(res.scalars().all())

        return items, total_count

    async def create_job(self, job: AnalysisJob) -> AnalysisJob:
        """Persist a new AnalysisJob."""
        self.session.add(job)
        await self.session.flush()
        return job
