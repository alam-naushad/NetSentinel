"""Telemetry and Historical Security Events API routes."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.db.repositories.event_repository import EventRepository
from app.db.repositories.job_repository import JobRepository
from app.schemas.pcap import PcapFlowProvenanceResponse
from app.schemas.telemetry import (
    AnalysisJobSummary,
    PageResponse,
    SecurityEventDetail,
    SecurityEventSummary,
    TelemetrySummaryStats,
)

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/events", response_model=PageResponse[SecurityEventSummary])
async def list_security_events(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=500, description="Items per page"),
    start_time: Optional[datetime] = Query(default=None, description="Start timestamp filter (ISO 8601)"),
    end_time: Optional[datetime] = Query(default=None, description="End timestamp filter (ISO 8601)"),
    severity: Optional[List[str]] = Query(default=None, description="Filter by severity levels"),
    triage_status: Optional[List[str]] = Query(default=None, description="Filter by triage statuses"),
    attack_family: Optional[List[str]] = Query(default=None, description="Filter by attack families"),
    src_ip: Optional[str] = Query(default=None, description="Source IP or CIDR prefix"),
    dst_ip: Optional[str] = Query(default=None, description="Destination IP or CIDR prefix"),
    src_port: Optional[int] = Query(default=None, ge=0, le=65535),
    dst_port: Optional[int] = Query(default=None, ge=0, le=65535),
    protocol: Optional[str] = Query(default=None, description="Protocol name (TCP/UDP)"),
    min_risk_score: Optional[int] = Query(default=None, ge=0, le=100),
    max_risk_score: Optional[int] = Query(default=None, ge=0, le=100),
    is_statistical_anomaly: Optional[bool] = Query(default=None),
    job_id: Optional[uuid.UUID] = Query(default=None, description="Filter by ingestion job ID"),
    sort_by: str = Query(default="event_timestamp", description="Field to sort by"),
    sort_order: str = Query(default="desc", description="Sort direction (asc/desc)"),
    db: Optional[AsyncSession] = Depends(get_db),
) -> PageResponse[SecurityEventSummary]:
    """Query historical security events with server-side pagination and multi-parameter filters."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    repo = EventRepository(db)
    items, total = await repo.search_events(
        page=page,
        page_size=page_size,
        start_time=start_time,
        end_time=end_time,
        severities=severity,
        triage_statuses=triage_status,
        attack_families=attack_family,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
        is_statistical_anomaly=is_statistical_anomaly,
        job_id=job_id,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    summaries: List[SecurityEventSummary] = []
    for ev in items:
        prov = ev.provenance
        summaries.append(
            SecurityEventSummary(
                id=ev.id,
                event_timestamp=ev.event_timestamp,
                source_channel=ev.source_channel,
                predicted_family=ev.predicted_family,
                class_confidence=round(ev.class_confidence, 4),
                normalized_anomaly_score=round(ev.normalized_anomaly_score, 4),
                is_statistical_anomaly=ev.is_statistical_anomaly,
                risk_score=ev.risk_score,
                severity=ev.severity,
                triage_status=ev.triage_status,
                src_ip=prov.src_ip if prov else "—",
                dst_ip=prov.dst_ip if prov else "—",
                src_port=prov.src_port if prov else 0,
                dst_port=prov.dst_port if prov else 0,
                protocol_name=prov.protocol_name if prov else "—",
                job_id=ev.job_id,
                has_alert=ev.alert is not None,
            )
        )

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return PageResponse(
        items=summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/events/{event_id}", response_model=SecurityEventDetail)
async def get_security_event_detail(
    event_id: uuid.UUID,
    db: Optional[AsyncSession] = Depends(get_db),
) -> SecurityEventDetail:
    """Retrieve full forensic details of a single security event including its 48-feature snapshot."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    repo = EventRepository(db)
    ev = await repo.get_by_id(event_id)
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID '{event_id}' was not found.",
        )

    prov = ev.provenance
    prov_resp = PcapFlowProvenanceResponse(
        flow_id=prov.flow_id if prov else "",
        src_ip=prov.src_ip if prov else "",
        dst_ip=prov.dst_ip if prov else "",
        src_port=prov.src_port if prov else 0,
        dst_port=prov.dst_port if prov else 0,
        ip_proto=prov.ip_proto if prov else 6,
        protocol_name=prov.protocol_name if prov else "TCP",
        start_time_iso=prov.start_time.isoformat() if prov else "",
        end_time_iso=prov.end_time.isoformat() if prov else "",
        duration_ms=prov.duration_ms if prov else 0.0,
        total_packets=prov.total_packets if prov else 0,
        total_bytes=prov.total_bytes if prov else 0,
    )

    dec = ev.decision
    return SecurityEventDetail(
        id=ev.id,
        event_timestamp=ev.event_timestamp,
        source_channel=ev.source_channel,
        predicted_family=ev.predicted_family,
        class_confidence=ev.class_confidence,
        class_probabilities=ev.class_probabilities,
        normalized_anomaly_score=ev.normalized_anomaly_score,
        raw_decision_score=dec.raw_decision_score if dec else 0.0,
        is_statistical_anomaly=ev.is_statistical_anomaly,
        risk_score=ev.risk_score,
        severity=ev.severity,
        triage_status=ev.triage_status,
        explanation=dec.explanation if dec else "",
        supervised_model_key=dec.supervised_model_key if dec else "protocol_a_xgboost_k48",
        anomaly_model_key=dec.anomaly_model_key if dec else "protocol_a_isolationforest_k48",
        provenance=prov_resp,
        feature_vector=ev.feature_vector,
        alert_id=ev.alert.id if ev.alert else None,
        job_id=ev.job_id,
    )


@router.get("/jobs", response_model=PageResponse[AnalysisJobSummary])
async def list_analysis_jobs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Optional[AsyncSession] = Depends(get_db),
) -> PageResponse[AnalysisJobSummary]:
    """List historical PCAP analysis jobs and ingestion runs."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    repo = JobRepository(db)
    items, total = await repo.list_jobs(page=page, page_size=page_size)

    summaries = [
        AnalysisJobSummary(
            id=j.id,
            source_type=j.source_type,
            filename=j.filename,
            file_size_bytes=j.file_size_bytes,
            file_sha256=j.file_sha256,
            total_flows_extracted=j.total_flows_extracted,
            total_flows_analyzed=j.total_flows_analyzed,
            anomalies_flagged=j.anomalies_flagged,
            processing_time_ms=j.processing_time_ms,
            status=j.status,
            created_at=j.created_at,
        )
        for j in items
    ]

    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return PageResponse(
        items=summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/jobs/{job_id}", response_model=AnalysisJobSummary)
async def get_analysis_job(
    job_id: uuid.UUID,
    db: Optional[AsyncSession] = Depends(get_db),
) -> AnalysisJobSummary:
    """Retrieve metadata and KPIs for a specific historical ingestion job."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    repo = JobRepository(db)
    job = await repo.get_by_id(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' was not found.",
        )

    return AnalysisJobSummary(
        id=job.id,
        source_type=job.source_type,
        filename=job.filename,
        file_size_bytes=job.file_size_bytes,
        file_sha256=job.file_sha256,
        total_flows_extracted=job.total_flows_extracted,
        total_flows_analyzed=job.total_flows_analyzed,
        anomalies_flagged=job.anomalies_flagged,
        processing_time_ms=job.processing_time_ms,
        status=job.status,
        created_at=job.created_at,
    )


@router.get("/stats/summary", response_model=TelemetrySummaryStats)
async def get_telemetry_summary_stats(
    time_window: str = Query(
        default="24h",
        description="Time window: 1h, 24h, 7d, 30d, all",
    ),
    db: Optional[AsyncSession] = Depends(get_db),
) -> TelemetrySummaryStats:
    """Retrieve aggregate security KPIs and threat distributions over a sliding time window."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )
    now = datetime.now(timezone.utc)
    start_time: Optional[datetime] = None

    if time_window == "1h":
        start_time = now - timedelta(hours=1)
    elif time_window == "24h":
        start_time = now - timedelta(days=1)
    elif time_window == "7d":
        start_time = now - timedelta(days=7)
    elif time_window == "30d":
        start_time = now - timedelta(days=30)
    elif time_window != "all":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time_window '{time_window}'. Allowed: 1h, 24h, 7d, 30d, all",
        )

    repo = EventRepository(db)
    stats = await repo.get_summary_stats(start_time=start_time, end_time=now)
    stats["time_window"] = time_window
    return TelemetrySummaryStats(**stats)
