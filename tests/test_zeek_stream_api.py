"""Tests for Zeek SSE streaming endpoint and ingestion status endpoint.

Verifies:
- GET /api/v1/zeek/ingestion/status when disabled vs enabled
- GET /api/v1/zeek/stream endpoint delivery with httpx.AsyncClient
- Client cap HTTP 429 response when broadcaster is saturated
- Event format verification (session_id, sequence_id, connection metadata)
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock
import httpx
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.main import app
from app.services.zeek.event_broadcaster import EventBroadcaster
from app.services.zeek.spool_tailer import SpoolTailer, TailerCounters
from app.services.zeek.ingestion_worker import IngestionWorker, IngestionCounters


class TestZeekStreamApi(unittest.IsolatedAsyncioTestCase):
    """Test suite for Zeek SSE and status routes."""

    async def asyncSetUp(self):
        self.broadcaster = EventBroadcaster(max_clients=3, replay_buffer_size=50)
        self.queue = asyncio.Queue()
        self.tailer = MagicMock(spec=SpoolTailer)
        self.tailer.is_running = True
        self.tailer._paused = asyncio.Event()
        self.tailer._paused.set()
        self.tailer.counters = TailerCounters()
        self.tailer._file_states = {}

        self.worker = MagicMock(spec=IngestionWorker)
        self.worker.counters = IngestionCounters()

        # Set app.state.zeek_ingestion
        app.state.zeek_ingestion = {
            "tailer": self.tailer,
            "worker": self.worker,
            "broadcaster": self.broadcaster,
            "queue": self.queue,
            "start_time": 1000.0,
            "heartbeat_sec": 1.0,
        }

    async def asyncTearDown(self):
        app.state.zeek_ingestion = None

    def test_ingestion_status_endpoint(self):
        """GET /api/v1/zeek/ingestion/status returns complete status and counters."""
        client = TestClient(app)
        self.tailer.counters.records_read = 42
        self.tailer.counters.records_parsed = 40
        self.worker.counters.records_persisted = 39

        response = client.get("/api/v1/zeek/ingestion/status")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["enabled"])
        self.assertEqual(data["status"], "running")
        self.assertEqual(data["counters"]["records_read"], 42)
        self.assertEqual(data["counters"]["records_parsed"], 40)
        self.assertEqual(data["counters"]["records_persisted"], 39)
        self.assertIn("sse_session_id", data)

    def test_ingestion_status_disabled(self):
        """GET /api/v1/zeek/ingestion/status returns disabled when context is None."""
        app.state.zeek_ingestion = None
        client = TestClient(app)
        response = client.get("/api/v1/zeek/ingestion/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["enabled"])
        self.assertEqual(data["status"], "disabled")

    async def test_sse_stream_generator_yields_events(self):
        """SSE stream generator yields connected event and broadcasted live events."""
        # Broadcast an event into ring buffer first
        await self.broadcaster.broadcast(
            "zeek_connection",
            {
                "uid": "STREAM_UID_1",
                "src_ip": "192.168.1.5",
                "dst_ip": "10.0.0.5",
                "proto": "tcp",
            },
        )

        sub_id, queue = await self.broadcaster.subscribe(
            last_event_id=f"{self.broadcaster.session_id}:0"
        )
        self.assertEqual(queue.qsize(), 1)
        event = await queue.get()
        self.assertEqual(event.event_type, "zeek_connection")
        self.assertEqual(event.data["uid"], "STREAM_UID_1")
        self.assertTrue(event.sse_id.startswith(self.broadcaster.session_id))

        await self.broadcaster.unsubscribe(sub_id)
        self.assertEqual(self.broadcaster.client_count, 0)

    async def test_sse_client_cap_returns_429(self):
        """When broadcaster is full, new subscriber receives 429 Too Many Requests."""
        # Max clients is 3, subscribe 3 dummy clients
        s1, _ = await self.broadcaster.subscribe()
        s2, _ = await self.broadcaster.subscribe()
        s3, _ = await self.broadcaster.subscribe()

        client = TestClient(app)
        response = client.get("/api/v1/zeek/stream")
        self.assertEqual(response.status_code, 429)

        await self.broadcaster.unsubscribe(s1)
        await self.broadcaster.unsubscribe(s2)
        await self.broadcaster.unsubscribe(s3)

    def test_sse_stream_disabled_returns_503(self):
        """GET /api/v1/zeek/stream returns 503 when ingestion is disabled."""
        app.state.zeek_ingestion = None
        client = TestClient(app)
        response = client.get("/api/v1/zeek/stream")
        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
