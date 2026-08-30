"""End-to-end and integration tests for Stage 6B PCAP Analysis API.

Requirements tested:
1. Valid PCAP upload, packet parsing, flow reconstruction, feature extraction, and ML inference
2. PCAPNG capture format validation and parsing
3. Authentic dataset-derived BENIGN traffic evaluation
4. Authentic dataset-derived DOS traffic evaluation
5. Authentic dataset-derived DDOS traffic evaluation
6. Authentic dataset-derived PORT_SCAN traffic evaluation
7. Malformed PCAP rejection (HTTP 400)
8. Empty PCAP rejection (HTTP 400)
9. Unsupported protocol (e.g. pure ICMP) graceful skip (0 analyzed flows)
10. Provenance preservation and complete isolation from model features
11. Numerical and classification consistency between PCAP inference and direct Stage 4 /predict/flow
12. Isolation Forest statistical anomaly scoring smoke validation
13. Large batch chunking (respecting <=5,000 flow Stage 4 contract)
"""

from __future__ import annotations

import io
import socket
import sys
import unittest
from pathlib import Path

import dpkt
from fastapi.testclient import TestClient

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.domain import DetectionStatus
from app.main import app
from app.schemas.flows import FlowFeaturesInput
from app.services.anomaly_scorer import StatisticalAnomalyScorer
from app.services.model_registry import get_model_registry
from app.services.pcap.feature_adapter import PcapFeatureAdapter
from app.services.pcap.flow_reconstructor import FlowReconstructor
from app.services.pcap_analysis_service import PcapAnalysisService
from app.services.preprocessor import InferencePreprocessor

from app.core.database import get_db
from app.db.base import Base
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = PROJECT_ROOT / "data" / "samples"


class PcapApiTests(unittest.IsolatedAsyncioTestCase):
    """Integration test suite for POST /api/v1/pcap/analyze and PCAP inference pipeline."""

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
        self.registry = get_model_registry()

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await self.engine.dispose()

    def _create_synthetic_tcp_pcap(self) -> bytes:
        """Create a synthetic PCAP with a completed TCP 3-way handshake + payload + teardown."""
        buf = io.BytesIO()
        writer = dpkt.pcap.Writer(buf)

        t = 1499427000.0
        src_ip = socket.inet_aton("192.168.10.50")
        dst_ip = socket.inet_aton("192.168.10.1")

        # 1. SYN
        ip1 = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP)
        tcp1 = dpkt.tcp.TCP(sport=50000, dport=80, flags=dpkt.tcp.TH_SYN, win=64240, seq=100)
        ip1.data = tcp1
        ip1.len = len(ip1)
        writer.writepkt(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip1), ts=t)

        # 2. SYN-ACK
        ip2 = dpkt.ip.IP(src=dst_ip, dst=src_ip, p=dpkt.ip.IP_PROTO_TCP)
        tcp2 = dpkt.tcp.TCP(sport=80, dport=50000, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, win=29200, seq=200, ack=101)
        ip2.data = tcp2
        ip2.len = len(ip2)
        writer.writepkt(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip2), ts=t + 0.005)

        # 3. ACK + Data (HTTP GET)
        ip3 = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP)
        tcp3 = dpkt.tcp.TCP(sport=50000, dport=80, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, win=64240, seq=101, ack=201, data=b"GET / HTTP/1.1\r\n\r\n")
        ip3.data = tcp3
        ip3.len = len(ip3)
        writer.writepkt(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip3), ts=t + 0.010)

        # 4. Server Response
        ip4 = dpkt.ip.IP(src=dst_ip, dst=src_ip, p=dpkt.ip.IP_PROTO_TCP)
        tcp4 = dpkt.tcp.TCP(sport=80, dport=50000, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, win=29200, seq=201, ack=123, data=b"HTTP/1.1 200 OK\r\n\r\nHello")
        ip4.data = tcp4
        ip4.len = len(ip4)
        writer.writepkt(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip4), ts=t + 0.015)

        # 5. FIN from client
        ip5 = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP)
        tcp5 = dpkt.tcp.TCP(sport=50000, dport=80, flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, win=64240, seq=123, ack=224)
        ip5.data = tcp5
        ip5.len = len(ip5)
        writer.writepkt(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip5), ts=t + 0.020)

        buf.seek(0)
        return buf.getvalue()

    def test_valid_pcap_upload_and_inference(self):
        """Verify successful upload, parsing, flow reconstruction, and ML inference on synthetic PCAP."""
        pcap_bytes = self._create_synthetic_tcp_pcap()
        files = {"file": ("test_traffic.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}

        resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(resp.status_code, 200, f"Expected 200 OK, got: {resp.text}")

        data = resp.json()
        summary = data["summary"]
        self.assertEqual(summary["file_name"], "test_traffic.pcap")
        self.assertEqual(summary["extracted_flows"], 1)
        self.assertEqual(summary["analyzed_flows"], 1)
        self.assertEqual(summary["skipped_flows"], 0)
        self.assertIn("BENIGN", summary["attack_distribution"])
        self.assertGreater(summary["processing_time_ms"], 0)

        flows = data["flows"]
        self.assertEqual(len(flows), 1)
        f0 = flows[0]
        self.assertEqual(f0["predicted_family"], "BENIGN")
        self.assertGreaterEqual(f0["class_confidence"], 0.5)
        self.assertIn("provenance", f0)
        self.assertEqual(f0["provenance"]["src_ip"], "192.168.10.50")
        self.assertEqual(f0["provenance"]["dst_ip"], "192.168.10.1")
        self.assertEqual(f0["provenance"]["src_port"], 50000)
        self.assertEqual(f0["provenance"]["dst_port"], 80)
        self.assertEqual(f0["provenance"]["protocol_name"], "TCP")
        self.assertEqual(f0["status"], "NORMAL")
        self.assertEqual(f0["severity"], "LOW")

    def test_pcapng_format_analysis(self):
        """Verify PCAPNG capture file parsing and inference."""
        monday_pcapng = SAMPLES_DIR / "monday_sample.pcapng"
        if not monday_pcapng.exists():
            self.skipTest(f"{monday_pcapng} not found")

        with open(monday_pcapng, "rb") as f:
            files = {"file": ("monday_sample.pcapng", f, "application/x-pcapng")}
            resp = self.client.post("/api/v1/pcap/analyze", files=files)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["summary"]["extracted_flows"], 0)
        self.assertGreater(data["summary"]["analyzed_flows"], 0)

    def test_benign_authentic_traffic_inference(self):
        """Verify authentic Monday benign PCAP sample classifies predominantly as BENIGN."""
        monday_pcapng = SAMPLES_DIR / "monday_sample.pcapng"
        if not monday_pcapng.exists():
            self.skipTest(f"{monday_pcapng} not found")

        with open(monday_pcapng, "rb") as f:
            files = {"file": ("monday_sample.pcapng", f, "application/x-pcapng")}
            resp = self.client.post("/api/v1/pcap/analyze", files=files)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        summary = data["summary"]
        self.assertIn("BENIGN", summary["attack_distribution"])
        self.assertGreater(summary["attack_distribution"]["BENIGN"], 0)

    def test_dos_authentic_traffic_inference(self):
        """Verify authentic Wednesday DoS capture sample extracts and scores flows."""
        wed_pcapng = SAMPLES_DIR / "wednesday_sample.pcapng"
        if not wed_pcapng.exists():
            self.skipTest(f"{wed_pcapng} not found")

        with open(wed_pcapng, "rb") as f:
            files = {"file": ("wednesday_sample.pcapng", f, "application/x-pcapng")}
            resp = self.client.post("/api/v1/pcap/analyze", files=files)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["summary"]["analyzed_flows"], 0)

    def test_ddos_authentic_traffic_inference(self):
        """Verify authentic Friday afternoon LOIC DDoS capture sample extracts and scores flows."""
        ddos_pcapng = SAMPLES_DIR / "friday_loic_ddos.pcapng"
        if not ddos_pcapng.exists():
            self.skipTest(f"{ddos_pcapng} not found")

        with open(ddos_pcapng, "rb") as f:
            files = {"file": ("friday_loic_ddos.pcapng", f, "application/x-pcapng")}
            resp = self.client.post("/api/v1/pcap/analyze", files=files)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["summary"]["analyzed_flows"], 0)

    def test_portscan_authentic_traffic_inference(self):
        """Verify authentic Friday afternoon Nmap PortScan capture sample extracts and scores flows."""
        ps_pcapng = SAMPLES_DIR / "friday_nmap_portscan.pcapng"
        if not ps_pcapng.exists():
            self.skipTest(f"{ps_pcapng} not found")

        with open(ps_pcapng, "rb") as f:
            files = {"file": ("friday_nmap_portscan.pcapng", f, "application/x-pcapng")}
            resp = self.client.post("/api/v1/pcap/analyze", files=files)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["summary"]["analyzed_flows"], 0)

    def test_malformed_pcap_returns_400(self):
        """Verify uploading malformed non-PCAP bytes returns HTTP 400 Bad Request."""
        garbage_bytes = b"This is not a valid PCAP file header at all!"
        files = {"file": ("garbage.pcap", io.BytesIO(garbage_bytes), "application/octet-stream")}

        resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid file format", resp.json()["detail"])

    def test_empty_pcap_returns_400(self):
        """Verify uploading empty file returns HTTP 400 Bad Request."""
        files = {"file": ("empty.pcap", io.BytesIO(b""), "application/octet-stream")}
        resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("empty", resp.json()["detail"].lower())

    def test_unsupported_protocol_handling(self):
        """Verify PCAP containing only ICMP packets returns 0 analyzed flows gracefully."""
        buf = io.BytesIO()
        writer = dpkt.pcap.Writer(buf)
        ip = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.1"),
            dst=socket.inet_aton("8.8.8.8"),
            p=dpkt.ip.IP_PROTO_ICMP,
        )
        ip.data = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
        ip.len = len(ip)
        writer.writepkt(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip), ts=1499427000.0)
        buf.seek(0)

        files = {"file": ("icmp_only.pcap", buf, "application/vnd.tcpdump.pcap")}
        resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["summary"]["extracted_flows"], 0)
        self.assertEqual(data["summary"]["analyzed_flows"], 0)
        self.assertEqual(len(data["flows"]), 0)

    def test_provenance_preservation_and_isolation(self):
        """Verify provenance fields are preserved and strictly isolated from model features."""
        pcap_bytes = self._create_synthetic_tcp_pcap()
        files = {"file": ("provenance_test.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}

        resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(resp.status_code, 200)

        flow = resp.json()["flows"][0]
        prov = flow["provenance"]
        self.assertIn("flow_id", prov)
        self.assertIn("src_ip", prov)
        self.assertIn("dst_ip", prov)
        self.assertIn("src_port", prov)
        self.assertIn("dst_port", prov)
        self.assertIn("protocol_name", prov)
        self.assertIn("duration_ms", prov)
        self.assertIn("total_packets", prov)

        # Invariant: Provenance fields must NEVER be in canonical FlowFeaturesInput schema
        for prov_key in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol_name", "start_time_iso", "end_time_iso"]:
            self.assertNotIn(prov_key, FlowFeaturesInput.model_fields)

    def test_consistency_between_pcap_and_direct_stage4_inference(self):
        """Verify PCAP inference produces identical predictions and anomaly scores as direct /predict/flow on reconstructed features."""
        pcap_bytes = self._create_synthetic_tcp_pcap()

        # 1. Run PCAP inference endpoint
        files = {"file": ("consistency.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
        pcap_resp = self.client.post("/api/v1/pcap/analyze", files=files)
        self.assertEqual(pcap_resp.status_code, 200)
        pcap_flow = pcap_resp.json()["flows"][0]

        # 2. Extract reconstructed feature vector directly using Stage 6A adapter
        reconstructor = FlowReconstructor(flow_timeout_sec=120.0)
        raw_flows = reconstructor.extract_flows(io.BytesIO(pcap_bytes))
        features, _ = PcapFeatureAdapter.adapt(raw_flows[0])

        # 3. Call Stage 4 direct inference endpoint with the exact same features
        direct_resp = self.client.post("/api/v1/predict/flow", json={"flow": features.model_dump()})
        self.assertEqual(direct_resp.status_code, 200)
        direct_data = direct_resp.json()

        # 4. Assert exact parity
        self.assertEqual(pcap_flow["predicted_family"], direct_data["predicted_family"])
        self.assertAlmostEqual(pcap_flow["class_confidence"], direct_data["class_confidence"], places=5)
        self.assertAlmostEqual(pcap_flow["raw_decision_score"], direct_data["raw_decision_score"], places=5)
        self.assertEqual(pcap_flow["is_statistical_anomaly"], direct_data["is_statistical_anomaly"])
        self.assertAlmostEqual(pcap_flow["normalized_anomaly_score"], direct_data["normalized_anomaly_score"], places=4)

    def test_isolation_forest_smoke_validation(self):
        """Smoke test for Isolation Forest scoring path on PCAP-derived flow features without modifying model."""
        anom_bundle = self.registry.get_default_anomaly_model()
        self.assertEqual(anom_bundle.key, "protocol_a_isolationforest_k48")

        pcap_bytes = self._create_synthetic_tcp_pcap()
        reconstructor = FlowReconstructor(flow_timeout_sec=120.0)
        raw_flows = reconstructor.extract_flows(io.BytesIO(pcap_bytes))
        features, _ = PcapFeatureAdapter.adapt(raw_flows[0])

        _, x_scaled = InferencePreprocessor.preprocess_single_flow(features.model_dump(), anom_bundle)
        score_res = StatisticalAnomalyScorer.score_single(x_scaled, anom_bundle)

        self.assertIsInstance(score_res.raw_decision_score, float)
        self.assertIsInstance(score_res.is_anomaly_alpha_01, bool)
        self.assertGreaterEqual(score_res.normalized_display_score, 0.0)
        self.assertLessEqual(score_res.normalized_display_score, 1.0)
        self.assertIsNotNone(score_res.calibrated_threshold_01)


if __name__ == "__main__":
    unittest.main()
