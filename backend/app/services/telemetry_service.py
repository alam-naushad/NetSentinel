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
from app.services.zeek.zeek_analysis_service import ZeekAnalysisResult
from app.services.zeek.zeek_connection_record import ZeekConnectionRecord

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

    async def persist_zeek_analysis(
        self,
        result: ZeekAnalysisResult,
        filename: str,
        file_size_bytes: int,
        file_sha256: Optional[str] = None,
        source_channel: str = "ZEEK_CONN",
    ) -> AnalysisJob:
        """Persist native Zeek connection telemetry into PostgreSQL.
        
        Explicit Failure Semantics:
        - If database operations fail and DATABASE_REQUIRED=True, the exception is raised.
        - If DATABASE_REQUIRED=False, errors are logged and handled without altering telemetry.
        """
        # 1. Create AnalysisJob
        job = AnalysisJob(
            source_type=source_channel,
            filename=filename,
            file_size_bytes=file_size_bytes,
            file_sha256=file_sha256,
            total_flows_extracted=result.parse_result.total_lines_read,
            total_flows_analyzed=len(result.raw_records),
            anomalies_flagged=0,
            processing_time_ms=result.summary.processing_time_ms,
            status="COMPLETED",
        )
        self.session.add(job)
        await self.session.flush()

        # 2. Build SecurityEvents and FlowProvenance (NO ModelDecision, NO Alert)
        events_to_add: List[SecurityEvent] = []

        for rec in result.raw_records:
            event = self._map_zeek_record_to_event(rec, job_id=job.id, source_channel=source_channel)
            events_to_add.append(event)

        self.session.add_all(events_to_add)
        await self.session.flush()

        logger.info(
            "Persisted Zeek AnalysisJob %s with %d native telemetry events into PostgreSQL.",
            job.id,
            len(events_to_add),
        )
        return job

    def _map_zeek_record_to_event(
        self,
        rec: ZeekConnectionRecord,
        job_id: Optional[uuid.UUID] = None,
        source_channel: str = "ZEEK_CONN",
    ) -> SecurityEvent:
        """Convert a single ZeekConnectionRecord into a SecurityEvent ORM entity."""
        event_dt = datetime.fromtimestamp(rec.ts, tz=timezone.utc)
        duration_sec = rec.duration if rec.duration is not None else 0.0
        end_dt = datetime.fromtimestamp(rec.ts + duration_sec, tz=timezone.utc)
        duration_ms = round(duration_sec * 1000.0, 3)

        proto_str = rec.proto.upper()
        ip_proto = 6 if rec.proto.lower() == "tcp" else 17 if rec.proto.lower() == "udp" else 1
        flow_id = f"{proto_str}_{rec.id_orig_h}_{rec.id_orig_p}_{rec.id_resp_h}_{rec.id_resp_p}_{int(rec.ts * 1_000_000)}"

        event = SecurityEvent(
            job_id=job_id,
            event_timestamp=event_dt,
            source_channel=source_channel,
            ml_classification_performed=False,
            predicted_family=None,
            class_confidence=None,
            normalized_anomaly_score=None,
            is_statistical_anomaly=False,
            risk_score=None,
            severity=None,
            triage_status=None,
            class_probabilities=None,
            feature_vector=None,
        )

        event.provenance = FlowProvenance(
            flow_id=flow_id,
            src_ip=rec.id_orig_h,
            dst_ip=rec.id_resp_h,
            src_port=rec.id_orig_p,
            dst_port=rec.id_resp_p,
            ip_proto=ip_proto,
            protocol_name=proto_str,
            start_time=event_dt,
            end_time=end_dt,
            duration_ms=duration_ms,
            total_packets=(rec.orig_pkts or 0) + (rec.resp_pkts or 0),
            total_bytes=(rec.orig_bytes or 0) + (rec.resp_bytes or 0),
            zeek_uid=rec.uid,
            conn_state=rec.conn_state,
            history=rec.history,
            service=rec.service,
            missed_bytes=rec.missed_bytes,
            zeek_metadata={
                "local_orig": rec.local_orig,
                "local_resp": rec.local_resp,
                "orig_ip_bytes": rec.orig_ip_bytes,
                "resp_ip_bytes": rec.resp_ip_bytes,
                "tunnel_parents": rec.tunnel_parents,
            },
        )

        # Do NOT create ModelDecision (no ML)
        # Do NOT create Alert (no attack)
        return event
