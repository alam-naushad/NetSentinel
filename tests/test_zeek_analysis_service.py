import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.future import select

from app.db.base import Base
from app.db.models.analysis_job import AnalysisJob
from app.db.models.security_event import SecurityEvent
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.model_decision import ModelDecision
from app.db.models.alert import Alert
from app.services.zeek.zeek_analysis_service import ZeekAnalysisService
from app.services.telemetry_service import TelemetryPersistenceService

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "zeek"

class TestZeekAnalysisService(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        
        self.sample_json = FIXTURES_DIR / "sample_conn.json"
        
    async def asyncTearDown(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    async def test_analysis_service_aggregations(self):
        with open(self.sample_json, "rb") as f:
            content = f.read()

        service = ZeekAnalysisService()
        result = service.analyze(content, "sample_conn.json", len(content), "fake_sha256")

        summary = result.summary
        self.assertEqual(summary.total_connections_parsed, 15)
        self.assertFalse(summary.ml_classification_performed)
        self.assertEqual(summary.analysis_type, "TELEMETRY_ONLY")
        self.assertIn("tcp", summary.protocol_distribution)
        self.assertIn("udp", summary.protocol_distribution)
        # Verify there is at least something in service_distribution
        self.assertGreater(len(summary.service_distribution), 0)
        self.assertIn("SF", summary.conn_state_distribution)

    async def test_zeek_persistence_to_database(self):
        with open(self.sample_json, "rb") as f:
            content = f.read()

        service = ZeekAnalysisService()
        result = service.analyze(content, "sample.json", len(content), "fake_sha256")

        async with self.session_factory() as session:
            persistence = TelemetryPersistenceService(session)
            job = await persistence.persist_zeek_analysis(result, "sample.json", len(content), "fake_sha256")
            await session.commit()
            
            # Query the database
            # Assert AnalysisJob created
            stmt = select(AnalysisJob).where(AnalysisJob.id == job.id)
            db_job = (await session.execute(stmt)).scalar_one()
            self.assertEqual(db_job.source_type, "ZEEK_CONN")
            self.assertEqual(db_job.total_flows_extracted, 15)
            self.assertEqual(db_job.total_flows_analyzed, 15)
            self.assertEqual(db_job.anomalies_flagged, 0)
            
            # Assert 15 SecurityEvent records created
            stmt = select(SecurityEvent).where(SecurityEvent.job_id == job.id)
            events = (await session.execute(stmt)).scalars().all()
            self.assertEqual(len(events), 15)
            
            for event in events:
                self.assertEqual(event.source_channel, "ZEEK_CONN")
                self.assertFalse(event.ml_classification_performed)
                self.assertIsNone(event.predicted_family)
                self.assertIsNone(event.class_confidence)
                self.assertIsNone(event.normalized_anomaly_score)
                self.assertIsNone(event.risk_score)
                self.assertIsNone(event.severity)
                self.assertIsNone(event.triage_status)
                self.assertIsNone(event.class_probabilities)
                self.assertIsNone(event.feature_vector)
                
            # Asserts 15 FlowProvenance records created
            stmt = select(FlowProvenance).join(SecurityEvent).where(SecurityEvent.job_id == job.id)
            provs = (await session.execute(stmt)).scalars().all()
            self.assertEqual(len(provs), 15)
            
            for prov in provs:
                self.assertIsNotNone(prov.zeek_uid)
                self.assertIsNotNone(prov.duration_ms)
                self.assertIsNotNone(prov.conn_state)
                self.assertIsNotNone(prov.zeek_metadata)
                
            # Asserts ZERO ModelDecision records exist for these events
            stmt = select(ModelDecision).join(SecurityEvent).where(SecurityEvent.job_id == job.id)
            decisions = (await session.execute(stmt)).scalars().all()
            self.assertEqual(len(decisions), 0)
            
            # Asserts ZERO Alert records exist for these events
            stmt = select(Alert).join(SecurityEvent).where(SecurityEvent.job_id == job.id)
            alerts = (await session.execute(stmt)).scalars().all()
            self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
