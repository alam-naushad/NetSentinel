"""PCAP analysis API routes.

POST /api/v1/pcap/analyze — Upload and analyze a PCAP/PCAPNG file.

Integrates downstream PostgreSQL persistence without modifying Stage 3-6B logic.
"""

from __future__ import annotations

import hashlib
import io
import logging
import tempfile
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.schemas.pcap import (
    PcapAnalysisResponse,
    PcapAnalysisSummary,
    PcapFlowDetailResult,
    PcapFlowProvenanceResponse,
    PcapFlowResult,
)
from app.services.pcap_analysis_service import PcapAnalysisService
from app.services.telemetry_service import TelemetryPersistenceService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["pcap"])

# Configuration constants
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FLOWS_PER_ANALYSIS = 10_000

# PCAP magic bytes: standard PCAP (big/little endian) and PCAPNG
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # PCAP little-endian
    b"\xa1\xb2\xc3\xd4",  # PCAP big-endian
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}


def _validate_pcap_magic(header: bytes) -> bool:
    """Validate that the file begins with a recognized PCAP or PCAPNG magic."""
    if len(header) < 4:
        return False
    return header[:4] in PCAP_MAGICS


@router.post("/pcap/analyze", response_model=PcapAnalysisResponse)
async def analyze_pcap(
    file: Annotated[UploadFile, File(description="PCAP or PCAPNG capture file")],
    db: AsyncSession = Depends(get_db),
) -> PcapAnalysisResponse:
    """Upload and analyze a PCAP/PCAPNG file through the validated ML inference pipeline.

    Pipeline: PCAP → packet parsing → stateful flow reconstruction → canonical 48-feature
    extraction → XGBoost K48 classification + Isolation Forest K48 anomaly detection
    → Hybrid Risk Engine → downstream PostgreSQL telemetry persistence → structured response.
    """
    filename = file.filename or "unknown.pcap"

    # Read file into memory-backed buffer with size limit enforcement
    spool = tempfile.SpooledTemporaryFile(max_size=5 * 1024 * 1024)
    total_read = 0
    sha256 = hashlib.sha256()

    try:
        while True:
            chunk = await file.read(65536)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > MAX_UPLOAD_BYTES:
                spool.close()
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File size exceeds maximum allowed limit of {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                )
            spool.write(chunk)
            sha256.update(chunk)
    except HTTPException:
        raise
    except Exception as e:
        spool.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {e}",
        ) from e

    if total_read == 0:
        spool.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # Validate PCAP/PCAPNG magic bytes
    spool.seek(0)
    header = spool.read(4)
    if not _validate_pcap_magic(header):
        spool.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Expected PCAP or PCAPNG capture file.",
        )
    spool.seek(0)

    # Step 1: Run the ML analysis pipeline (Stage 6A + Stage 4)
    try:
        service = PcapAnalysisService(
            flow_timeout_sec=120.0,
            max_flows=MAX_FLOWS_PER_ANALYSIS,
        )
        result = service.analyze(spool)
    except Exception as e:
        logger.error("PCAP analysis failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"PCAP analysis failed: {e}",
        ) from e
    finally:
        spool.close()

    # Step 2: Downstream PostgreSQL persistence
    file_hash = sha256.hexdigest()
    persisted = False
    job_id_str: Optional[str] = None
    persistence_error: Optional[str] = None

    if db is not None:
        try:
            telemetry_svc = TelemetryPersistenceService(db)
            job = await telemetry_svc.persist_pcap_analysis(
                result=result,
                filename=filename,
                file_size_bytes=total_read,
                file_sha256=file_hash,
                source_channel="PCAP_BATCH",
            )
            persisted = True
            job_id_str = str(job.id)
        except Exception as e:
            try:
                await db.rollback()
            except Exception:
                pass
            persistence_error = str(e)
            logger.warning("Downstream PostgreSQL persistence failed: %s", e)
            if settings.DATABASE_REQUIRED:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Inference succeeded but database persistence failed (DATABASE_REQUIRED=true): {e}",
                ) from e

    # Step 3: Build response
    flow_results: list[PcapFlowResult] = []
    for af in result.analyzed_flows:
        prov = PcapFlowProvenanceResponse(
            flow_id=af.provenance.flow_id,
            src_ip=af.provenance.src_ip,
            dst_ip=af.provenance.dst_ip,
            src_port=af.provenance.src_port,
            dst_port=af.provenance.dst_port,
            ip_proto=af.provenance.ip_proto,
            protocol_name=af.provenance.protocol_name,
            start_time_iso=af.provenance.start_time_iso,
            end_time_iso=af.provenance.end_time_iso,
            duration_ms=af.provenance.duration_ms,
            total_packets=af.provenance.total_packets,
            total_bytes=af.provenance.total_bytes,
        )

        flow_results.append(
            PcapFlowResult(
                provenance=prov,
                predicted_family=af.predicted_family,
                class_confidence=af.class_confidence,
                class_probabilities=af.class_probabilities,
                raw_decision_score=af.raw_decision_score,
                is_statistical_anomaly=af.is_statistical_anomaly,
                normalized_anomaly_score=af.normalized_anomaly_score,
                risk_score=af.risk_score,
                severity=af.severity,
                status=af.status,
                explanation=af.explanation,
                features=af.features.model_dump(),
            )
        )

    summary = PcapAnalysisSummary(
        file_name=filename,
        file_size_bytes=total_read,
        extracted_flows=result.extracted_flow_count,
        analyzed_flows=result.analyzed_flow_count,
        skipped_flows=result.skipped_flow_count,
        attack_distribution=result.attack_distribution,
        severity_distribution=result.severity_distribution,
        status_distribution=result.status_distribution,
        anomalies_flagged=result.anomalies_flagged,
        processing_time_ms=result.processing_time_ms,
        supervised_model_key=result.supervised_model_key,
        anomaly_model_key=result.anomaly_model_key,
        job_id=job_id_str,
        persisted=persisted,
        persistence_error=persistence_error,
    )

    return PcapAnalysisResponse(summary=summary, flows=flow_results)
