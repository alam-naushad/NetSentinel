"""Integration tests for Historical Telemetry and Alerts APIs."""

from __future__ import annotations

import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.database import get_db
from app.db.base import Base
from app.db.models.alert import Alert, AlertHistory
from app.db.models.analysis_job import AnalysisJob
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.model_decision import ModelDecision
from app.db.models.security_event import SecurityEvent
from app.main import app


class TelemetryApiTests(unittest.IsolatedAsyncioTestCase):
    """Test suite for /api/v1/telemetry and /api/v1/alerts endpoints."""

    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

        # Override get_db dependency in FastAPI app
        async def override_get_db():
            async with self.session_factory() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Seed sample job, event, and alert
        async with self.session_factory() as session:
            job = AnalysisJob(
                filename="capture_sample.pcapng",
                file_size_bytes=20480,
                file_sha256="sha256_mock_hash",
                total_flows_extracted=5,
                total_flows_analyzed=5,
                anomalies_flagged=1,
                processing_time_ms=80.0,
            )
            session.add(job)
            await session.flush()
            self.seeded_job_id = job.id

            event = SecurityEvent(
                job_id=job.id,
                event_timestamp=datetime.now(timezone.utc),
                source_channel="PCAP_BATCH",
                predicted_family="DDOS",
                class_confidence=0.97,
                normalized_anomaly_score=0.65,
                is_statistical_anomaly=True,
                risk_score=85,
                severity="CRITICAL",
                triage_status="KNOWN_ATTACK",
                class_probabilities={"BENIGN": 0.02, "DDOS": 0.97, "DOS": 0.01},
                feature_vector={"destination_port": 80.0, "flow_bytes_per_sec": 50000.0},
            )
            event.provenance = FlowProvenance(
                flow_id="TCP_10.0.0.5_44321_10.0.0.1_80",
                src_ip="10.0.0.5",
                dst_ip="10.0.0.1",
                src_port=44321,
                dst_port=80,
                ip_proto=6,
                protocol_name="TCP",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                duration_ms=120.0,
                total_packets=30,
                total_bytes=8400,
            )
            event.decision = ModelDecision(
                supervised_model_key="protocol_a_xgboost_k48",
                anomaly_model_key="protocol_a_isolationforest_k48",
                raw_decision_score=-0.085,
                calibrated_threshold=0.051838,
                policy_version="production-v1.0",
                explanation="High-confidence volumetric DDoS flood identified.",
            )

            alert = Alert(
                alert_type="KNOWN_ATTACK_DDOS",
                severity="CRITICAL",
                disposition="OPEN",
                analyst_notes=None,
                policy_version_applied="policy-alert-v1.0",
            )
            alert.history.append(
                AlertHistory(
                    timestamp=datetime.now(timezone.utc),
                    previous_disposition=None,
                    new_disposition="OPEN",
                    actor_id="system",
                    action_note="Triggered on DDoS flow",
                )
            )
            event.alert = alert

            session.add(event)
            await session.commit()
            self.seeded_event_id = event.id
            self.seeded_alert_id = alert.id

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    def test_list_events_and_filtering(self):
        """Verify GET /api/v1/telemetry/events pagination and multi-parameter filters."""
        # 1. Fetch all events
        resp = self.client.get("/api/v1/telemetry/events?page=1&page_size=20")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(len(data["items"]), 1)
        item = data["items"][0]
        self.assertEqual(item["predicted_family"], "DDOS")
        self.assertEqual(item["severity"], "CRITICAL")
        self.assertEqual(item["src_ip"], "10.0.0.5")

        # 2. Filter matching criteria
        resp_match = self.client.get("/api/v1/telemetry/events?attack_family=DDOS&min_risk_score=80")
        self.assertEqual(resp_match.status_code, 200)
        self.assertEqual(resp_match.json()["total"], 1)

        # 3. Filter non-matching criteria
        resp_nomatch = self.client.get("/api/v1/telemetry/events?attack_family=PORT_SCAN")
        self.assertEqual(resp_nomatch.status_code, 200)
        self.assertEqual(resp_nomatch.json()["total"], 0)

    def test_get_event_detail(self):
        """Verify GET /api/v1/telemetry/events/{id} returns complete forensic record including 48 features."""
        resp = self.client.get(f"/api/v1/telemetry/events/{self.seeded_event_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], str(self.seeded_event_id))
        self.assertIn("feature_vector", data)
        self.assertEqual(data["feature_vector"]["destination_port"], 80.0)
        self.assertIn("provenance", data)
        self.assertEqual(data["provenance"]["protocol_name"], "TCP")

    def test_list_jobs_and_job_detail(self):
        """Verify GET /api/v1/telemetry/jobs and GET /api/v1/telemetry/jobs/{id}."""
        resp = self.client.get("/api/v1/telemetry/jobs")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["filename"], "capture_sample.pcapng")

        # Get job by ID
        resp_detail = self.client.get(f"/api/v1/telemetry/jobs/{self.seeded_job_id}")
        self.assertEqual(resp_detail.status_code, 200)
        self.assertEqual(resp_detail.json()["total_flows_analyzed"], 5)

    def test_get_telemetry_summary_stats(self):
        """Verify GET /api/v1/telemetry/stats/summary returns aggregated threat metrics."""
        resp = self.client.get("/api/v1/telemetry/stats/summary?time_window=all")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_events"], 1)
        self.assertEqual(data["total_attacks"], 1)
        self.assertIn("DDOS", data["attack_distribution"])

    def test_list_alerts_and_patch_disposition(self):
        """Verify GET /api/v1/alerts and PATCH /api/v1/alerts/{id} with audit trail appending."""
        # 1. List alerts
        resp = self.client.get("/api/v1/alerts?disposition=OPEN")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["total"], 1)

        # 2. Update disposition: OPEN -> INVESTIGATING
        patch_payload = {
            "new_disposition": "INVESTIGATING",
            "actor_id": "analyst_bob",
            "note": "Beginning packet-level trace inspection",
        }
        resp_patch = self.client.patch(f"/api/v1/alerts/{self.seeded_alert_id}", json=patch_payload)
        self.assertEqual(resp_patch.status_code, 200)
        alert_data = resp_patch.json()
        self.assertEqual(alert_data["disposition"], "INVESTIGATING")
        self.assertEqual(len(alert_data["history"]), 2)
        self.assertEqual(alert_data["history"][1]["new_disposition"], "INVESTIGATING")
        self.assertEqual(alert_data["history"][1]["actor_id"], "analyst_bob")

        # 3. Subsequent GET in a fresh request / session: verify history persistence
        resp_get = self.client.get(f"/api/v1/alerts/{self.seeded_alert_id}")
        self.assertEqual(resp_get.status_code, 200)
        get_data = resp_get.json()
        self.assertEqual(get_data["disposition"], "INVESTIGATING")
        self.assertEqual(len(get_data["history"]), 2)
        self.assertEqual(get_data["history"][0]["new_disposition"], "OPEN")
        self.assertEqual(get_data["history"][1]["new_disposition"], "INVESTIGATING")
        self.assertEqual(get_data["history"][1]["actor_id"], "analyst_bob")
        self.assertEqual(get_data["history"][1]["action_note"], "Beginning packet-level trace inspection")


if __name__ == "__main__":
    unittest.main()
