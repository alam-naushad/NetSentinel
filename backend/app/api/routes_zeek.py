"""Zeek Native Telemetry API routes.

POST /api/v1/zeek/analyze - Upload and parse a Zeek log (conn.log).
"""

import hashlib
import logging
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.schemas.zeek import ZeekAnalysisResponse
from app.services.zeek.zeek_analysis_service import ZeekAnalysisService
from app.services.telemetry_service import TelemetryPersistenceService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["zeek"])


@router.post("/zeek/analyze", response_model=ZeekAnalysisResponse)
async def analyze_zeek(
    file: Annotated[UploadFile, File(description="Zeek conn.log file")],
    db: Optional[AsyncSession] = Depends(get_db),
) -> ZeekAnalysisResponse:
    """Upload and analyze a Zeek conn.log file."""
    filename = file.filename or "conn.log"
    
    # Calculate limits from settings (assuming ZEEK_MAX_UPLOAD_SIZE_MB is available, fallback to 50MB)
    max_size_mb = getattr(settings, "ZEEK_MAX_UPLOAD_SIZE_MB", 50)
    max_upload_bytes = max_size_mb * 1024 * 1024
    
    content = bytearray()
    total_read = 0
    sha256 = hashlib.sha256()

    try:
        while True:
            chunk = await file.read(65536)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_upload_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File size exceeds maximum allowed limit of {max_size_mb} MB.",
                )
            content.extend(chunk)
            sha256.update(chunk)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {e}",
        ) from e

    if total_read == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    file_hash = sha256.hexdigest()
    
    try:
        service = ZeekAnalysisService()
        result = service.analyze(
            file_content=bytes(content),
            filename=filename,
            file_size_bytes=total_read,
            file_sha256=file_hash
        )
    except Exception as e:
        logger.error("Zeek log analysis failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Zeek log parsing failed: {e}",
        ) from e

    if not result.raw_records and result.parse_result.total_lines_read > 0:
        # parsed some lines but no valid connections (maybe malformed)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No valid connections found in the provided Zeek log file.",
        )

    job_id: Optional[uuid.UUID] = None
    persisted = False
    persistence_error: Optional[str] = None

    if db is not None:
        try:
            telemetry_svc = TelemetryPersistenceService(db)
            job = await telemetry_svc.persist_zeek_analysis(
                result=result,
                filename=filename,
                file_size_bytes=total_read,
                file_sha256=file_hash,
            )
            persisted = True
            job_id = job.id
            result.summary.total_connections_persisted = len(result.raw_records)
        except Exception as e:
            try:
                await db.rollback()
            except Exception:
                pass
            persistence_error = str(e)
            logger.warning("Downstream PostgreSQL persistence failed for Zeek log: %s", e)
            if getattr(settings, "DATABASE_REQUIRED", False):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Database persistence failed: {e}",
                ) from e

    return ZeekAnalysisResponse(
        summary=result.summary,
        connections=result.connections,
        job_id=job_id,
        persisted=persisted,
        persistence_error=persistence_error
    )
