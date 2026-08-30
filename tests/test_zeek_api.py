import sys
import io
import os
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.core.database import get_db
from app.db.base import Base

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "zeek"

class TestZeekApi(unittest.IsolatedAsyncioTestCase):
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
        
        self.sample_json = FIXTURES_DIR / "sample_conn.json"
        self.sample_tsv = FIXTURES_DIR / "sample_conn.tsv"
        self.malformed_log = FIXTURES_DIR / "malformed_conn.log"

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    def test_upload_json_conn_log(self):
        with open(self.sample_json, "rb") as f:
            files = {"file": ("sample_conn.json", f, "application/json")}
            response = self.client.post("/api/v1/zeek/analyze", files=files)
            
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["summary"]["total_connections_parsed"], 15)
        self.assertFalse(data["summary"]["ml_classification_performed"])
        self.assertEqual(data["summary"]["analysis_type"], "TELEMETRY_ONLY")
        self.assertTrue(data["persisted"])
        self.assertIsInstance(data["job_id"], str)

    def test_upload_tsv_conn_log(self):
        with open(self.sample_tsv, "rb") as f:
            files = {"file": ("sample_conn.tsv", f, "text/tab-separated-values")}
            response = self.client.post("/api/v1/zeek/analyze", files=files)
            
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["summary"]["total_connections_parsed"], 15)
        self.assertTrue(data["persisted"])

    def test_empty_file_rejected(self):
        files = {"file": ("empty.log", io.BytesIO(b""), "application/octet-stream")}
        response = self.client.post("/api/v1/zeek/analyze", files=files)
        self.assertEqual(response.status_code, 400)

    def test_malformed_file_partial_success(self):
        with open(self.malformed_log, "rb") as f:
            files = {"file": ("malformed_conn.log", f, "application/octet-stream")}
            response = self.client.post("/api/v1/zeek/analyze", files=files)
            
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(data["summary"]["connections_skipped_malformed"], 0)
        self.assertTrue(data["persisted"])

    def test_file_size_exceeded(self):
        from unittest.mock import patch
        with patch("app.api.routes_zeek.settings") as mock_settings:
            mock_settings.ZEEK_MAX_UPLOAD_SIZE_MB = 0
            files = {"file": ("large.log", io.BytesIO(b"some large content that exceeds 0 MB"), "application/octet-stream")}
            response = self.client.post("/api/v1/zeek/analyze", files=files)
            self.assertEqual(response.status_code, 413)

if __name__ == "__main__":
    unittest.main()
