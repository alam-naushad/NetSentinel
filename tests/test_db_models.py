"""Unit tests for SQLAlchemy Database Models and Entity Relationships.

Uses in-memory SQLite (sqlite+aiosqlite) for fast dialect-neutral constraint validation.
"""

from __future__ import annotations

import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.db.base import Base
from app.db.models.alert import Alert, AlertHistory
from app.db.models.analysis_job import AnalysisJob
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.model_decision import ModelDecision
from app.db.models.security_event import SecurityEvent


class DbModelTests(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying ORM mappings, constraints, and cascade lifecycles."""

    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    async def test_create_and_link_full_security_event_graph(self):
        """Verify full entity creation, foreign key resolution, and 1-to-1 relationships."""
        async with self.session_factory() as session:
            # 1. Create AnalysisJob
            job = AnalysisJob(
                filename="test_traffic.pcap",
                file_size_bytes=10240,
                file_sha256="abc123sha256",
                total_flows_extracted=10,
                total_flows_analyzed=10,
                anomalies_flagged=2,
                processing_time_ms=150.5,
            )
            session.add(job)
            await session.flush()

            # 2. Create SecurityEvent linked to job
            event = SecurityEvent(
                job_id=job.id,
                event_timestamp=datetime.now(timezone.utc),
                source_channel="PCAP_BATCH",
                predicted_family="DOS",
                class_confidence=0.985,
                normalized_anomaly_score=0.75,
                is_statistical_anomaly=True,
                risk_score=88,
                severity="CRITICAL",
                triage_status="KNOWN_ATTACK",
                class_probabilities={"BENIGN": 0.01, "DOS": 0.985, "DDOS": 0.005},
                feature_vector={"destination_port": 80.0, "total_forward_packets": 50.0},
            )

            # 3. Attach FlowProvenance
            event.provenance = FlowProvenance(
                flow_id="TCP_192.168.1.100_50000_192.168.1.1_80",
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=50000,
                dst_port=80,
                ip_proto=6,
                protocol_name="TCP",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                duration_ms=250.0,
                total_packets=50,
                total_bytes=12500,
            )

            # 4. Attach ModelDecision
            event.decision = ModelDecision(
                supervised_model_key="protocol_a_xgboost_k48",
                anomaly_model_key="protocol_a_isolationforest_k48",
                raw_decision_score=-0.1245,
                calibrated_threshold=0.051838,
                policy_version="production-v1.0",
                explanation="High-confidence DoS attack detected.",
            )

            # 5. Attach Alert and initial history
            alert = Alert(
                alert_type="KNOWN_ATTACK_DOS",
                severity="CRITICAL",
                disposition="OPEN",
                analyst_notes="Generated on high confidence DoS",
                policy_version_applied="policy-alert-v1.0",
            )
            alert.history.append(
                AlertHistory(
                    timestamp=datetime.now(timezone.utc),
                    previous_disposition=None,
                    new_disposition="OPEN",
                    actor_id="system",
                    action_note="Initial alert creation",
                )
            )
            event.alert = alert

            session.add(event)
            await session.commit()

            # Verify retrieval
            retrieved = await session.get(SecurityEvent, event.id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.predicted_family, "DOS")
            self.assertEqual(retrieved.job_id, job.id)
            self.assertEqual(retrieved.provenance.src_ip, "192.168.1.100")
            self.assertEqual(retrieved.decision.supervised_model_key, "protocol_a_xgboost_k48")
            self.assertIsNotNone(retrieved.alert)
            self.assertEqual(retrieved.alert.disposition, "OPEN")
            self.assertEqual(len(retrieved.alert.history), 1)

    async def test_alert_append_only_history_preservation(self):
        """Verify updating alert disposition appends to AlertHistory without overwriting past entries."""
        async with self.session_factory() as session:
            event = SecurityEvent(
                predicted_family="PORT_SCAN",
                class_confidence=0.92,
                normalized_anomaly_score=0.40,
                is_statistical_anomaly=False,
                risk_score=75,
                severity="HIGH",
                triage_status="KNOWN_ATTACK",
                class_probabilities={"PORT_SCAN": 0.92},
                feature_vector={"destination_port": 22.0},
            )
            alert = Alert(
                alert_type="ATTACK_PORT_SCAN",
                severity="HIGH",
                disposition="OPEN",
                policy_version_applied="policy-alert-v1.0",
            )
            alert.history.append(
                AlertHistory(
                    new_disposition="OPEN",
                    actor_id="system",
                    action_note="Initial alert",
                )
            )
            event.alert = alert
            session.add(event)
            await session.commit()

            # Perform 1st update: OPEN -> INVESTIGATING
            alert.disposition = "INVESTIGATING"
            alert.history.append(
                AlertHistory(
                    previous_disposition="OPEN",
                    new_disposition="INVESTIGATING",
                    actor_id="analyst_alice",
                    action_note="Triaging port scan from internal IP",
                )
            )
            await session.commit()

            # Perform 2nd update: INVESTIGATING -> RESOLVED
            alert.disposition = "RESOLVED"
            alert.resolved_at = datetime.now(timezone.utc)
            alert.history.append(
                AlertHistory(
                    previous_disposition="INVESTIGATING",
                    new_disposition="RESOLVED",
                    actor_id="analyst_alice",
                    action_note="Vulnerability scan verified and authorized",
                )
            )
            await session.commit()

            # Verify complete 3-entry audit trail
            loaded_alert = await session.get(Alert, alert.id)
            self.assertEqual(loaded_alert.disposition, "RESOLVED")
            self.assertEqual(len(loaded_alert.history), 3)
            self.assertEqual(loaded_alert.history[0].new_disposition, "OPEN")
            self.assertEqual(loaded_alert.history[1].new_disposition, "INVESTIGATING")
            self.assertEqual(loaded_alert.history[2].new_disposition, "RESOLVED")


if __name__ == "__main__":
    unittest.main()
