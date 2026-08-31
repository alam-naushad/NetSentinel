"""Tests for Observability, Health Probes, and Structured Logging.

Verifies:
- Minimal /health/live probe
- Guarded /health/ready readiness probe
- Operational metrics endpoint /api/v1/metrics
- JSONLogFormatter structure and JSON formatting
"""

import json
import logging
import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.main import app
from app.core.logging_config import JSONLogFormatter


class TestObservability(unittest.TestCase):
    """Test suite for health probes, metrics, and structured logging."""

    def setUp(self):
        self.client = TestClient(app)

    def test_health_live_minimal_response(self):
        """GET /health/live returns a minimal liveness heartbeat."""
        response = self.client.get("/health/live")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "network-anomaly-api")
        # Ensure no internal paths or sensitive details are exposed
        self.assertNotIn("database_url", data)
        self.assertNotIn("models_dir", data)

    def test_health_ready_probe(self):
        """GET /health/ready returns guarded readiness diagnostics."""
        response = self.client.get("/health/ready")
        self.assertIn(response.status_code, [200, 503])
        data = response.json()
        self.assertIn("status", data)
        self.assertIn("database", data)
        self.assertIn("models", data)
        self.assertIn("environment", data)
        # Ensure no internal connection strings or stack traces are leaked
        self.assertNotIn("password", str(data).lower())
        self.assertNotIn("traceback", str(data).lower())

    def test_metrics_endpoint(self):
        """GET /api/v1/metrics returns operational platform telemetry."""
        response = self.client.get("/api/v1/metrics")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("uptime_seconds", data)
        self.assertIn("platform_version", data)
        self.assertIn("models_loaded", data)
        self.assertIn("sse_clients_connected", data)
        self.assertIn("zeek_queue_depth", data)
        self.assertGreaterEqual(data["uptime_seconds"], 0.0)

    def test_json_log_formatter(self):
        """JSONLogFormatter formats records as valid single-line JSON objects."""
        formatter = JSONLogFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Security audit event: %s",
            args=("login_success",),
            exc_info=None,
        )

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        self.assertEqual(parsed["level"], "INFO")
        self.assertEqual(parsed["logger"], "test.logger")
        self.assertIn("Security audit event: login_success", parsed["message"])
        self.assertIn("timestamp", parsed)
        self.assertIn("environment", parsed)


if __name__ == "__main__":
    unittest.main()
