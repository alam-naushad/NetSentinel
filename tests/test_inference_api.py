"""Integration tests for FastAPI inference and evaluation endpoints."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.domain import DetectionStatus
from app.main import app

# Deterministic Network Flow Fixtures (Exactly 48 selected features)
BENIGN_FIXTURE = {
    "psh_flag_count": 0.0,
    "bwd_packet_length_mean": 0.0,
    "min_seg_size_fwd": 20.0,
    "bwd_packet_length_std": 0.0,
    "bwd_packet_length_min": 0.0,
    "max_packet_length": 6.0,
    "destination_port": 49188.0,
    "ack_flag_count": 1.0,
    "packet_length_mean": 6.0,
    "fwd_iat_std": 0.0,
    "idle_min": 0.0,
    "init_win_bytes_fwd": 329.0,
    "packet_length_variance": 0.0,
    "min_packet_length": 6.0,
    "fwd_packet_length_max": 6.0,
    "act_data_pkt_fwd": 1.0,
    "flow_iat_std": 0.0,
    "total_forward_packets": 2.0,
    "down_up_ratio": 0.0,
    "flow_iat_mean": 4.0,
    "avg_fwd_segment_size": 6.0,
    "fwd_header_length": 40.0,
    "bwd_header_length": 0.0,
    "fwd_iat_total": 4.0,
    "fin_flag_count": 0.0,
    "bwd_iat_total": 0.0,
    "fwd_packets_per_sec": 500000.0,
    "urg_flag_count": 1.0,
    "init_win_bytes_bwd": -1.0,
    "fwd_iat_mean": 4.0,
    "fwd_packet_length_min": 6.0,
    "total_forward_bytes": 12.0,
    "bwd_packets_per_sec": 0.0,
    "syn_flag_count": 0.0,
    "bwd_iat_max": 0.0,
    "bwd_iat_mean": 0.0,
    "bwd_iat_std": 0.0,
    "active_mean": 0.0,
    "flow_bytes_per_sec": 3000000.0,
    "active_min": 0.0,
    "flow_iat_min": 4.0,
    "active_max": 0.0,
    "fwd_iat_min": 4.0,
    "idle_std": 0.0,
    "bwd_iat_min": 0.0,
    "active_std": 0.0,
    "fwd_urg_flags": 0.0,
    "ece_flag_count": 0.0,
}

DOS_FIXTURE = {
    "psh_flag_count": 1.0,
    "bwd_packet_length_mean": 0.0,
    "min_seg_size_fwd": 32.0,
    "bwd_packet_length_std": 0.0,
    "bwd_packet_length_min": 0.0,
    "max_packet_length": 231.0,
    "destination_port": 80.0,
    "ack_flag_count": 0.0,
    "packet_length_mean": 33.0,
    "fwd_iat_std": 292511.09375,
    "idle_min": 0.0,
    "init_win_bytes_fwd": 29200.0,
    "packet_length_variance": 7623.0,
    "min_packet_length": 0.0,
    "fwd_packet_length_max": 231.0,
    "act_data_pkt_fwd": 1.0,
    "flow_iat_std": 226626.5625,
    "total_forward_packets": 4.0,
    "down_up_ratio": 0.0,
    "flow_iat_mean": 101532.203125,
    "avg_fwd_segment_size": 57.75,
    "fwd_header_length": 136.0,
    "bwd_header_length": 72.0,
    "fwd_iat_total": 507661.0,
    "fin_flag_count": 0.0,
    "bwd_iat_total": 694.0,
    "fwd_packets_per_sec": 7.879273891448975,
    "urg_flag_count": 0.0,
    "init_win_bytes_bwd": 235.0,
    "fwd_iat_mean": 169220.328125,
    "fwd_packet_length_min": 0.0,
    "total_forward_bytes": 231.0,
    "bwd_packets_per_sec": 3.9396369457244873,
    "syn_flag_count": 0.0,
    "bwd_iat_max": 694.0,
    "bwd_iat_mean": 694.0,
    "bwd_iat_std": 0.0,
    "active_mean": 0.0,
    "flow_bytes_per_sec": 455.0280456542969,
    "active_min": 0.0,
    "flow_iat_min": 33.0,
    "active_max": 0.0,
    "fwd_iat_min": 182.0,
    "idle_std": 0.0,
    "bwd_iat_min": 694.0,
    "active_std": 0.0,
    "fwd_urg_flags": 0.0,
    "ece_flag_count": 0.0,
}

PORTSCAN_FIXTURE = {
    "psh_flag_count": 1.0,
    "bwd_packet_length_mean": 2.0,
    "min_seg_size_fwd": 20.0,
    "bwd_packet_length_std": 0.0,
    "bwd_packet_length_min": 2.0,
    "max_packet_length": 6.0,
    "destination_port": 80.0,
    "ack_flag_count": 0.0,
    "packet_length_mean": 3.0,
    "fwd_iat_std": 0.0,
    "idle_min": 0.0,
    "init_win_bytes_fwd": 1024.0,
    "packet_length_variance": 4.0,
    "min_packet_length": 2.0,
    "fwd_packet_length_max": 6.0,
    "act_data_pkt_fwd": 1.0,
    "flow_iat_std": 296.2777404785156,
    "total_forward_packets": 2.0,
    "down_up_ratio": 0.0,
    "flow_iat_mean": 335.5,
    "avg_fwd_segment_size": 4.0,
    "fwd_header_length": 44.0,
    "bwd_header_length": 24.0,
    "fwd_iat_total": 671.0,
    "fin_flag_count": 0.0,
    "bwd_iat_total": 0.0,
    "fwd_packets_per_sec": 2980.6259765625,
    "urg_flag_count": 0.0,
    "init_win_bytes_bwd": 29200.0,
    "fwd_iat_mean": 671.0,
    "fwd_packet_length_min": 2.0,
    "total_forward_bytes": 8.0,
    "bwd_packets_per_sec": 1490.31298828125,
    "syn_flag_count": 0.0,
    "bwd_iat_max": 0.0,
    "bwd_iat_mean": 0.0,
    "bwd_iat_std": 0.0,
    "active_mean": 0.0,
    "flow_bytes_per_sec": 14903.1298828125,
    "active_min": 0.0,
    "flow_iat_min": 126.0,
    "active_max": 0.0,
    "fwd_iat_min": 671.0,
    "idle_std": 0.0,
    "bwd_iat_min": 0.0,
    "active_std": 0.0,
    "fwd_urg_flags": 0.0,
    "ece_flag_count": 0.0,
}

DDOS_FIXTURE = {
    "psh_flag_count": 1.0,
    "bwd_packet_length_mean": 1658.142822265625,
    "min_seg_size_fwd": 20.0,
    "bwd_packet_length_std": 2137.297119140625,
    "bwd_packet_length_min": 0.0,
    "max_packet_length": 5840.0,
    "destination_port": 80.0,
    "ack_flag_count": 0.0,
    "packet_length_mean": 1057.54541015625,
    "fwd_iat_std": 523.9661254882812,
    "idle_min": 0.0,
    "init_win_bytes_fwd": 8192.0,
    "packet_length_variance": 3435230.75,
    "min_packet_length": 0.0,
    "fwd_packet_length_max": 20.0,
    "act_data_pkt_fwd": 2.0,
    "flow_iat_std": 430865.8125,
    "total_forward_packets": 3.0,
    "down_up_ratio": 2.0,
    "flow_iat_mean": 143754.671875,
    "avg_fwd_segment_size": 8.666666984558105,
    "fwd_header_length": 72.0,
    "bwd_header_length": 152.0,
    "fwd_iat_total": 747.0,
    "fin_flag_count": 0.0,
    "bwd_iat_total": 1293746.0,
    "fwd_packets_per_sec": 2.31876540184021,
    "urg_flag_count": 0.0,
    "init_win_bytes_bwd": 229.0,
    "fwd_iat_mean": 373.5,
    "fwd_packet_length_min": 0.0,
    "total_forward_bytes": 26.0,
    "bwd_packets_per_sec": 5.410452365875244,
    "syn_flag_count": 0.0,
    "bwd_iat_max": 1292730.0,
    "bwd_iat_mean": 215624.328125,
    "bwd_iat_std": 527671.9375,
    "active_mean": 0.0,
    "flow_bytes_per_sec": 8991.3994140625,
    "active_min": 0.0,
    "flow_iat_min": 2.0,
    "active_max": 0.0,
    "fwd_iat_min": 3.0,
    "idle_std": 0.0,
    "bwd_iat_min": 2.0,
    "active_std": 0.0,
    "fwd_urg_flags": 0.0,
    "ece_flag_count": 0.0,
}


class InferenceApiTests(unittest.TestCase):
    """Test suite for FastAPI endpoints: health, models catalog, inference, and decision triage."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_health_endpoint(self) -> None:
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "network-anomaly-api")

    def test_models_catalog_endpoint(self) -> None:
        response = self.client.get("/api/v1/models")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_models"], 16)
        self.assertEqual(data["default_supervised_model"], "protocol_a_xgboost_k48")
        self.assertEqual(data["default_anomaly_model"], "protocol_a_isolationforest_k48")
        self.assertEqual(len(data["models"]), 16)

    def test_single_flow_prediction_benign(self) -> None:
        payload = {"flow": BENIGN_FIXTURE}
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["predicted_family"], "BENIGN")
        self.assertGreater(data["class_confidence"], 0.80)
        self.assertIn("BENIGN", data["class_probabilities"])
        # Regression check: verify BENIGN has highest probability (not INFILTRATION or any other class)
        probs = data["class_probabilities"]
        self.assertGreater(probs["BENIGN"], 0.99)
        max_prob_class = max(probs, key=probs.get)
        self.assertEqual(max_prob_class, "BENIGN")
        self.assertGreater(probs["BENIGN"], probs.get("INFILTRATION", 0.0) * 1000)
        self.assertIsInstance(data["raw_decision_score"], float)
        self.assertIsInstance(data["is_statistical_anomaly"], bool)
        self.assertGreater(data["inference_latency_ms"], 0.0)

    def test_single_flow_prediction_dos(self) -> None:
        payload = {"flow": DOS_FIXTURE}
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["predicted_family"], "DOS")
        self.assertGreater(data["class_confidence"], 0.90)

    def test_single_flow_prediction_ddos(self) -> None:
        """Deterministic inference test for authentic DDOS flow fixture."""
        payload = {"flow": DDOS_FIXTURE}
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["predicted_family"], "DDOS")
        self.assertGreater(data["class_confidence"], 0.90)

    def test_single_flow_prediction_portscan(self) -> None:
        payload = {"flow": PORTSCAN_FIXTURE}
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["predicted_family"], "PORT_SCAN")
        self.assertGreater(data["class_confidence"], 0.90)

    def test_batch_flow_inference(self) -> None:
        payload = {"flows": [BENIGN_FIXTURE, DOS_FIXTURE, DDOS_FIXTURE, PORTSCAN_FIXTURE]}
        response = self.client.post("/api/v1/predict/batch", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_flows"], 4)
        self.assertEqual(len(data["predictions"]), 4)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"].get("BENIGN"), 1)
        self.assertEqual(data["summary"].get("DOS"), 1)
        self.assertEqual(data["summary"].get("DDOS"), 1)
        self.assertEqual(data["summary"].get("PORT_SCAN"), 1)

    def test_missing_feature_returns_422_with_names(self) -> None:
        broken_flow = BENIGN_FIXTURE.copy()
        del broken_flow["destination_port"]
        del broken_flow["psh_flag_count"]

        payload = {"flow": broken_flow}
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertIn("detail", data)

    def test_non_finite_returns_422(self) -> None:
        broken_flow = BENIGN_FIXTURE.copy()
        broken_flow["packet_length_mean"] = "NaN"  # type: ignore

        payload = {"flow": broken_flow}
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 422)

    def test_batch_limit_validation(self) -> None:
        # Pydantic max_length=5000 enforces limit at gateway
        oversized = [BENIGN_FIXTURE] * 5001
        payload = {"flows": oversized}
        response = self.client.post("/api/v1/predict/batch", json=payload)
        self.assertEqual(response.status_code, 422)

    def test_evaluate_flow_hybrid_decision_benign(self) -> None:
        payload = {
            "flow": BENIGN_FIXTURE,
            "context": {"repeated_source_events": 0, "targets_sensitive_service": False},
        }
        response = self.client.post("/api/v1/decisions/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"]["status"], DetectionStatus.NORMAL.value)
        self.assertEqual(data["prediction"]["predicted_family"], "BENIGN")
        self.assertLess(data["decision"]["risk_score"], 40)

    def test_evaluate_flow_hybrid_decision_dos(self) -> None:
        payload = {
            "flow": DOS_FIXTURE,
            "context": {"repeated_source_events": 3, "targets_sensitive_service": True},
        }
        response = self.client.post("/api/v1/decisions/evaluate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["decision"]["status"], DetectionStatus.KNOWN_ATTACK.value)
        self.assertEqual(data["prediction"]["predicted_family"], "DOS")
        self.assertGreaterEqual(data["decision"]["risk_score"], 65)

    def test_port_ablation_model_selection(self) -> None:
        payload = {
            "flow": DOS_FIXTURE,
            "supervised_model_key": "protocol_a_xgboost_k47",
        }
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["supervised_model_key"], "protocol_a_xgboost_k47")
        self.assertEqual(data["predicted_family"], "DOS")

    def test_unknown_model_selection_404(self) -> None:
        payload = {
            "flow": BENIGN_FIXTURE,
            "supervised_model_key": "non_existent_unregistered_model",
        }
        response = self.client.post("/api/v1/predict/flow", json=payload)
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
