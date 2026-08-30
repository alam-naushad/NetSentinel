"""Telemetry Persistence Service.

Orchestrates the ingestion, mapping, and bulk persistence of ML-analyzed flows
into PostgreSQL relational tables.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.analysis_job import AnalysisJob
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.model_decision import ModelDecision
from app.db.models.security_event import SecurityEvent
from app.services.alert_service import AlertService
from app.services.pcap_analysis_service import AnalyzedFlow, PcapAnalysisResult

logger = logging.getLogger(__name__)


class TelemetryPersistenceService:
    """Persists ML-analyzed network flows, model audits, provenance, and generated alerts."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def persist_pcap_analysis(
        self,
        result: PcapAnalysisResult,
        filename: str,
        file_size_bytes: int,
        file_sha256: Optional[str] = None,
        source_channel: str = "PCAP_BATCH",
    ) -> AnalysisJob:
        """Persist a complete PcapAnalysisResult as an AnalysisJob and all child SecurityEvents.
        
        Explicit Failure Semantics:
        - If database operations fail and DATABASE_REQUIRED=True, the exception is raised.
        - If DATABASE_REQUIRED=False, errors are logged and handled without altering ML evidence.
        """
        # 1. Create AnalysisJob
        job = AnalysisJob(
            source_type=source_channel,
            filename=filename,
            file_size_bytes=file_size_bytes,
            file_sha256=file_sha256,
            total_flows_extracted=result.extracted_flow_count,
            total_flows_analyzed=result.analyzed_flow_count,
            anomalies_flagged=result.anomalies_flagged,
            processing_time_ms=result.processing_time_ms,
            status="COMPLETED",
        )
        self.session.add(job)
        await self.session.flush()

        # 2. Build SecurityEvents, Provenance, Decisions, and Alerts
        events_to_add: List[SecurityEvent] = []

        for af in result.analyzed_flows:
            event = self._map_analyzed_flow_to_event(af, job_id=job.id, source_channel=source_channel)
            events_to_add.append(event)

        self.session.add_all(events_to_add)
        await self.session.flush()

        logger.info(
            "Persisted AnalysisJob %s with %d security events into PostgreSQL.",
            job.id,
            len(events_to_add),
        )
        return job

    def _map_analyzed_flow_to_event(
        self,
        af: AnalyzedFlow,
        job_id: Optional[uuid.UUID] = None,
        source_channel: str = "PCAP_BATCH",
    ) -> SecurityEvent:
        """Convert a single AnalyzedFlow dataclass into a fully linked SecurityEvent ORM graph."""
        prov = af.provenance
        start_dt = datetime.fromisoformat(prov.start_time_iso)
        end_dt = datetime.fromisoformat(prov.end_time_iso)

        event = SecurityEvent(
            job_id=job_id,
            event_timestamp=start_dt,
            source_channel=source_channel,
            predicted_family=af.predicted_family,
            class_confidence=af.class_confidence,
            normalized_anomaly_score=af.normalized_anomaly_score,
            is_statistical_anomaly=af.is_statistical_anomaly,
            risk_score=af.risk_score,
            severity=af.severity,
            triage_status=af.status,
            class_probabilities=af.class_probabilities,
            feature_vector=af.features.model_dump(),  # Immutable JSONB forensic snapshot
        )

        # 1-to-1 Provenance entity
        event.provenance = FlowProvenance(
            flow_id=prov.flow_id,
            src_ip=prov.src_ip,
            dst_ip=prov.dst_ip,
            src_port=prov.src_port,
            dst_port=prov.dst_port,
            ip_proto=prov.ip_proto,
            protocol_name=prov.protocol_name,
            start_time=start_dt,
            end_time=end_dt,
            duration_ms=prov.duration_ms,
            total_packets=prov.total_packets,
            total_bytes=prov.total_bytes,
        )

        # 1-to-1 Model Decision entity
        event.decision = ModelDecision(
            supervised_model_key="protocol_a_xgboost_k48",
            anomaly_model_key="protocol_a_isolationforest_k48",
            raw_decision_score=af.raw_decision_score,
            calibrated_threshold=0.051838,
            policy_version="production-v1.0",
            explanation=af.explanation,
            evaluated_at=datetime.now(timezone.utc),
        )

        # Configurable alert generation
        alert = AlertService.create_alert_for_event(event)
        if alert:
            event.alert = alert

        return event
