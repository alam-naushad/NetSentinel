"""Integration test verifying PCAP upload with downstream database persistence."""

from __future__ import annotations

import io
import socket
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
import dpkt
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.database import get_db
from app.db.base import Base
from app.db.models.analysis_job import AnalysisJob
from app.db.models.security_event import SecurityEvent
from app.main import app


class PcapPersistenceTests(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying end-to-end PCAP upload -> ML inference -> DB persistence."""

    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

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

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    def _create_synthetic_pcap(self) -> bytes:
        buf = io.BytesIO()
        writer = dpkt.pcap.Writer(buf)
        t = 1499427000.0

        # TCP flow 1: Port 80 HTTP
        ip1 = dpkt.ip.IP(src=socket.inet_aton("192.168.1.50"), dst=socket.inet_aton("192.168.1.1"), p=6)
        tcp1 = dpkt.tcp.TCP(sport=50000, dport=80, flags=dpkt.tcp.TH_SYN, win=64240, seq=100)
        ip1.data = tcp1
        ip1.len = len(ip1)
        writer.writepkt(dpkt.ethernet.Ethernet(data=ip1), ts=t)

        ip2 = dpkt.ip.IP(src=socket.inet_aton("192.168.1.1"), dst=socket.inet_aton("192.168.1.50"), p=6)
        tcp2 = dpkt.tcp.TCP(sport=80, dport=50000, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, win=29200, seq=200, ack=101)
        ip2.data = tcp2
        ip2.len = len(ip2)
        writer.writepkt(dpkt.ethernet.Ethernet(data=ip2), ts=t + 0.005)

        ip3 = dpkt.ip.IP(src=socket.inet_aton("192.168.1.50"), dst=socket.inet_aton("192.168.1.1"), p=6)
        tcp3 = dpkt.tcp.TCP(sport=50000, dport=80, flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, win=64240, seq=101, ack=201)
        ip3.data = tcp3
        ip3.len = len(ip3)
        writer.writepkt(dpkt.ethernet.Ethernet(data=ip3), ts=t + 0.010)

        buf.seek(0)
        return buf.getvalue()

    def test_pcap_upload_persists_to_database(self):
        """Verify uploading PCAP persists AnalysisJob and SecurityEvent records."""
        pcap_bytes = self._create_synthetic_pcap()
        files = {"file": ("persistence_test.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}

        resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        summary = data["summary"]
        self.assertTrue(summary["persisted"], "Analysis should be persisted to DB")
        self.assertIsNotNone(summary["job_id"], "job_id must be populated")

        # Query telemetry events endpoint to confirm event is in DB
        events_resp = self.client.get(f"/api/v1/telemetry/events?job_id={summary['job_id']}")
        self.assertEqual(events_resp.status_code, 200)
        events_data = events_resp.json()
        self.assertEqual(events_data["total"], 1)
        self.assertEqual(events_data["items"][0]["src_ip"], "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
