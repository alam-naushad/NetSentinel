"""Quantitative Unit Tests and Empirical Evaluation for Zeek Feature Completeness & Safe Routing.

Verifies:
1. Single source of truth & schema consistency across selected_features.json, FlowFeaturesInput, and model metadata.
2. Complete and incomplete feature vectors.
3. Missing, null, placeholder, and non-numeric values.
4. NaN and infinite numeric values.
5. Domain constraints (port range, non-negative metrics, permitted signed features).
6. Extra and unexpected feature keys.
7. Dictionary key insertion ordering invariance.
8. Dual-gate source compatibility vs schema completeness.
9. Native Zeek conn.log routing to TELEMETRY_ONLY.
10. Unverified ZEEK_FLOWMETER routing to TELEMETRY_ONLY pending semantic parity calibration.
11. Untrusted client source spoofing prevention.
12. Strict isolation: TELEMETRY_ONLY flows never invoke ML models or fabricate predictions.
13. Empirical evaluation on real repository fixture (tests/fixtures/zeek/sample_conn.json).
"""

from __future__ import annotations

import json
import math
import random
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.schemas.flows import FlowFeaturesInput
from app.schemas.zeek import RoutingDecision, TrustedSourceChannel
from app.services.model_registry import get_model_registry
from app.services.zeek.feature_completeness import (
    CANONICAL_48_FEATURES,
    CANONICAL_48_SET,
    SIGNED_FEATURES,
    VALIDATED_ML_COMPATIBLE_SOURCES,
    evaluate_feature_completeness,
    extract_canonical_feature_vector,
    route_flow,
    safe_route_and_evaluate,
    validate_feature_value,
    verify_canonical_schema_consistency,
)


def make_valid_48_dict() -> dict[str, float]:
    """Generate a synthetically complete and valid 48-feature dictionary."""
    return {
        "psh_flag_count": 2.0,
        "bwd_packet_length_mean": 128.5,
        "min_seg_size_fwd": 20.0,
        "bwd_packet_length_std": 45.2,
        "bwd_packet_length_min": 0.0,
        "max_packet_length": 1460.0,
        "destination_port": 443.0,
        "ack_flag_count": 8.0,
        "packet_length_mean": 95.0,
        "fwd_iat_std": 1200.0,
        "idle_min": 0.0,
        "init_win_bytes_fwd": 65535.0,
        "packet_length_variance": 5400.0,
        "min_packet_length": 0.0,
        "fwd_packet_length_max": 512.0,
        "act_data_pkt_fwd": 3.0,
        "flow_iat_std": 850.0,
        "total_forward_packets": 6.0,
        "down_up_ratio": 1.5,
        "flow_iat_mean": 500.0,
        "avg_fwd_segment_size": 85.0,
        "fwd_header_length": 120.0,
        "bwd_header_length": 160.0,
        "fwd_iat_total": 3000.0,
        "fin_flag_count": 1.0,
        "bwd_iat_total": 4500.0,
        "fwd_packets_per_sec": 12.0,
        "urg_flag_count": 0.0,
        "init_win_bytes_bwd": 29200.0,
        "fwd_iat_mean": 600.0,
        "fwd_packet_length_min": 0.0,
        "total_forward_bytes": 510.0,
        "bwd_packets_per_sec": 18.0,
        "syn_flag_count": 1.0,
        "bwd_iat_max": 2000.0,
        "bwd_iat_mean": 900.0,
        "bwd_iat_std": 400.0,
        "active_mean": 0.0,
        "flow_bytes_per_sec": 4200.0,
        "active_min": 0.0,
        "flow_iat_min": 10.0,
        "active_max": 0.0,
        "fwd_iat_min": 25.0,
        "idle_std": 0.0,
        "bwd_iat_min": 15.0,
        "active_std": 0.0,
        "fwd_urg_flags": 0.0,
        "ece_flag_count": 0.0,
    }


class TestZeekFeatureCompletenessScoring(unittest.TestCase):
    """Test suite for feature completeness evaluation and safe routing logic."""

    def setUp(self):
        self.valid_flow = make_valid_48_dict()

    # --------------------------------------------------------------------------
    # 1. Single Source of Truth & Consistency Tests
    # --------------------------------------------------------------------------

    def test_schema_consistency_with_metadata_file(self):
        """Assert CANONICAL_48_FEATURES matches data/metadata/selected_features.json exactly."""
        meta_path = PROJECT_ROOT / "data" / "metadata" / "selected_features.json"
        self.assertTrue(meta_path.exists())
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        selected = tuple(meta["selected_features"])
        self.assertEqual(len(selected), 48)
        self.assertEqual(CANONICAL_48_FEATURES, selected)
        self.assertTrue(verify_canonical_schema_consistency(meta_path))

    def test_schema_consistency_with_flow_features_input(self):
        """Assert CANONICAL_48_FEATURES matches FlowFeaturesInput model fields exactly."""
        pydantic_fields = tuple(FlowFeaturesInput.model_fields.keys())
        self.assertEqual(len(pydantic_fields), 48)
        self.assertEqual(CANONICAL_48_FEATURES, pydantic_fields)

    def test_schema_consistency_with_production_models(self):
        """Assert CANONICAL_48_FEATURES matches feature_names in production model bundles."""
        registry = get_model_registry()
        sup_bundle = registry.get_default_supervised_model()
        anom_bundle = registry.get_default_anomaly_model()

        self.assertEqual(CANONICAL_48_FEATURES, tuple(sup_bundle.feature_names))
        self.assertEqual(CANONICAL_48_FEATURES, tuple(anom_bundle.feature_names))

    # --------------------------------------------------------------------------
    # 2. Complete and Incomplete Feature Vectors
    # --------------------------------------------------------------------------

    def test_complete_48_features_from_compatible_source(self):
        """All 48 valid features from a compatible source route to ML_INFERENCE."""
        report = evaluate_feature_completeness(self.valid_flow)
        self.assertEqual(report.valid_features_count, 48)
        self.assertEqual(report.completeness_score, 1.0)
        self.assertTrue(report.is_eligible_for_ml)
        self.assertEqual(report.missing_features, [])
        self.assertEqual(report.invalid_features, {})

        # Route from trusted compatible source
        res = route_flow(
            self.valid_flow,
            source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED,
        )
        self.assertEqual(res.route, RoutingDecision.ML_INFERENCE)
        self.assertTrue(res.is_eligible_for_ml)
        self.assertIsNotNone(res.feature_vector)
        self.assertEqual(len(res.feature_vector), 48)

    def test_single_missing_feature_boundary(self):
        """Omitting exactly 1 feature produces completeness 47/48 and routes to TELEMETRY_ONLY."""
        flow = dict(self.valid_flow)
        del flow["destination_port"]

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 47)
        self.assertAlmostEqual(report.completeness_score, 47 / 48.0, places=5)
        self.assertFalse(report.is_eligible_for_ml)
        self.assertEqual(report.missing_features, ["destination_port"])

        res = route_flow(
            flow,
            source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED,
        )
        self.assertEqual(res.route, RoutingDecision.TELEMETRY_ONLY)
        self.assertFalse(res.is_eligible_for_ml)
        self.assertIsNone(res.feature_vector)
        self.assertIn("destination_port", res.completeness.missing_features)

    def test_multiple_missing_features(self):
        """Omitting 5 features produces completeness 43/48 and routes to TELEMETRY_ONLY."""
        flow = dict(self.valid_flow)
        omitted = [
            "psh_flag_count",
            "bwd_packet_length_mean",
            "fwd_iat_std",
            "idle_min",
            "active_std",
        ]
        for f in omitted:
            del flow[f]

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 43)
        self.assertAlmostEqual(report.completeness_score, 43 / 48.0, places=5)
        self.assertFalse(report.is_eligible_for_ml)
        self.assertEqual(sorted(report.missing_features), sorted(omitted))

        res = route_flow(
            flow,
            source_channel=TrustedSourceChannel.REST_INFERENCE,
        )
        self.assertEqual(res.route, RoutingDecision.TELEMETRY_ONLY)
        self.assertFalse(res.is_eligible_for_ml)

    # --------------------------------------------------------------------------
    # 3. Missing, Null, Placeholder, and Malformed Values
    # --------------------------------------------------------------------------

    def test_null_value_rejected(self):
        """None value is rejected from valid count and reported in invalid_features."""
        flow = dict(self.valid_flow)
        flow["packet_length_mean"] = None

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 47)
        self.assertIn("packet_length_mean", report.invalid_features)
        self.assertIn("value is None", report.invalid_features["packet_length_mean"])

    def test_empty_string_and_placeholder_dash_rejected(self):
        """String placeholders ('', '-', '(empty)', 'null') are rejected."""
        placeholders = ["", "-", "  ", "(empty)", "null", "none"]
        for p in placeholders:
            flow = dict(self.valid_flow)
            flow["fwd_iat_mean"] = p
            report = evaluate_feature_completeness(flow)
            self.assertEqual(report.valid_features_count, 47)
            self.assertIn("fwd_iat_mean", report.invalid_features)

    def test_non_numeric_string_rejected(self):
        """Arbitrary non-numeric strings ('abc', 'error') fail float conversion."""
        flow = dict(self.valid_flow)
        flow["total_forward_packets"] = "invalid_text"

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 47)
        self.assertIn("total_forward_packets", report.invalid_features)
        self.assertIn("invalid numeric type", report.invalid_features["total_forward_packets"])

    def test_boolean_type_strictly_rejected(self):
        """Booleans (True/False) are strictly rejected as measurements."""
        flow = dict(self.valid_flow)
        flow["syn_flag_count"] = True  # bool subclass of int in Python

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 47)
        self.assertIn("syn_flag_count", report.invalid_features)
        self.assertIn("boolean type rejected", report.invalid_features["syn_flag_count"])

    # --------------------------------------------------------------------------
    # 4. NaN and Infinite Values
    # --------------------------------------------------------------------------

    def test_nan_value_rejected(self):
        """NaN value is rejected and reported in invalid_features."""
        flow = dict(self.valid_flow)
        flow["flow_iat_std"] = float("nan")

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 47)
        self.assertIn("flow_iat_std", report.invalid_features)
        self.assertIn("non-finite", report.invalid_features["flow_iat_std"])

    def test_positive_and_negative_infinity_rejected(self):
        """+inf and -inf values are strictly rejected."""
        flow = dict(self.valid_flow)
        flow["flow_bytes_per_sec"] = float("inf")
        flow["bwd_packets_per_sec"] = float("-inf")

        report = evaluate_feature_completeness(flow)
        self.assertEqual(report.valid_features_count, 46)
        self.assertIn("flow_bytes_per_sec", report.invalid_features)
        self.assertIn("bwd_packets_per_sec", report.invalid_features)

    # --------------------------------------------------------------------------
    # 5. Domain Constraints (Supported Domain Rules)
    # --------------------------------------------------------------------------

    def test_destination_port_domain_bounds(self):
        """destination_port must be in [0, 65535]."""
        # Port > 65535 rejected
        flow_high = dict(self.valid_flow)
        flow_high["destination_port"] = 65536.0
        rep_high = evaluate_feature_completeness(flow_high)
        self.assertIn("destination_port", rep_high.invalid_features)
        self.assertIn("out of bounds", rep_high.invalid_features["destination_port"])

        # Port < 0 rejected
        flow_low = dict(self.valid_flow)
        flow_low["destination_port"] = -1.0
        rep_low = evaluate_feature_completeness(flow_low)
        self.assertIn("destination_port", rep_low.invalid_features)

        # Port = 0 or 65535 accepted
        flow_edge = dict(self.valid_flow)
        flow_edge["destination_port"] = 0.0
        self.assertEqual(evaluate_feature_completeness(flow_edge).valid_features_count, 48)

    def test_non_negative_metrics_reject_negative_values(self):
        """Strictly non-negative features reject values < 0.0."""
        non_negative_candidates = [
            "psh_flag_count",
            "bwd_packet_length_mean",
            "flow_iat_mean",
            "total_forward_bytes",
            "fwd_iat_min",
        ]
        for feat in non_negative_candidates:
            flow = dict(self.valid_flow)
            flow[feat] = -5.0
            rep = evaluate_feature_completeness(flow)
            self.assertEqual(rep.valid_features_count, 47)
            self.assertIn(feat, rep.invalid_features)
            self.assertIn("must be non-negative", rep.invalid_features[feat])

    def test_permitted_signed_features_accept_negative_values(self):
        """Permitted signed features (init_win_bytes_fwd/bwd, header lengths) accept negative values."""
        flow = dict(self.valid_flow)
        flow["init_win_bytes_fwd"] = -1.0  # Common for non-SYN flows / UDP
        flow["init_win_bytes_bwd"] = -1.0
        flow["fwd_header_length"] = -40.0   # Training set anomaly preservation
        flow["bwd_header_length"] = -20.0

        rep = evaluate_feature_completeness(flow)
        self.assertEqual(rep.valid_features_count, 48)
        self.assertEqual(rep.completeness_score, 1.0)
        self.assertTrue(rep.is_eligible_for_ml)

    # --------------------------------------------------------------------------
    # 6. Extra Keys and Key Ordering Invariance
    # --------------------------------------------------------------------------

    def test_unexpected_keys_tracked_without_affecting_score(self):
        """Extra keys outside canonical schema are reported in unexpected_features."""
        flow = dict(self.valid_flow)
        flow["custom_analyst_tag"] = "suspicious_host"
        flow["unknown_metric_x"] = 999.0

        rep = evaluate_feature_completeness(flow)
        self.assertEqual(rep.valid_features_count, 48)
        self.assertEqual(rep.completeness_score, 1.0)
        self.assertTrue(rep.is_eligible_for_ml)
        self.assertIn("custom_analyst_tag", rep.unexpected_features)
        self.assertIn("unknown_metric_x", rep.unexpected_features)

    def test_dictionary_key_ordering_invariance(self):
        """Arbitrary dict insertion order produces identical completeness and canonical vector."""
        # 1. Canonical order
        canonical_dict = {f: self.valid_flow[f] for f in CANONICAL_48_FEATURES}

        # 2. Reversed order
        reversed_dict = {f: self.valid_flow[f] for f in reversed(CANONICAL_48_FEATURES)}

        # 3. Randomly shuffled order (seeded for reproducibility)
        shuffled_keys = list(CANONICAL_48_FEATURES)
        random.Random(42).shuffle(shuffled_keys)
        shuffled_dict = {f: self.valid_flow[f] for f in shuffled_keys}

        # Assert all 3 dictionaries evaluate to identical completeness
        rep_c = evaluate_feature_completeness(canonical_dict)
        rep_r = evaluate_feature_completeness(reversed_dict)
        rep_s = evaluate_feature_completeness(shuffled_dict)
        self.assertEqual(rep_c.completeness_score, 1.0)
        self.assertEqual(rep_r.completeness_score, 1.0)
        self.assertEqual(rep_s.completeness_score, 1.0)

        # Assert extracted 1D numpy vectors are bit-for-bit identical
        vec_c = extract_canonical_feature_vector(
            canonical_dict, source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED
        )
        vec_r = extract_canonical_feature_vector(
            reversed_dict, source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED
        )
        vec_s = extract_canonical_feature_vector(
            shuffled_dict, source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED
        )

        self.assertEqual(vec_c.shape, (48,))
        self.assertTrue((vec_c == vec_r).all())
        self.assertTrue((vec_c == vec_s).all())

        # Assert vector elements match CANONICAL_48_FEATURES in exact sequence
        for idx, feat in enumerate(CANONICAL_48_FEATURES):
            self.assertEqual(vec_c[idx], self.valid_flow[feat])

    # --------------------------------------------------------------------------
    # 7. Dual-Gate Safe Routing & Source Incompatibility
    # --------------------------------------------------------------------------

    def test_native_zeek_conn_log_routing_to_telemetry_only(self):
        """Native Zeek conn.log payload is strictly routed to TELEMETRY_ONLY."""
        native_conn_record = {
            "ts": 1525879832.0,
            "uid": "CHhAvVGS1DHF508n6",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 45123,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.5,
            "orig_bytes": 1200,
            "resp_bytes": 4500,
            "conn_state": "SF",
        }

        res = route_flow(
            native_conn_record,
            source_channel=TrustedSourceChannel.ZEEK_CONN,
        )

        self.assertEqual(res.route, RoutingDecision.TELEMETRY_ONLY)
        self.assertFalse(res.is_eligible_for_ml)
        self.assertFalse(res.ml_classification_performed)
        self.assertIsNone(res.feature_vector)
        self.assertIn("ZEEK_CONN", res.routing_reason)
        # Provenance is preserved
        self.assertEqual(res.telemetry_preserved.get("uid"), "CHhAvVGS1DHF508n6")
        self.assertEqual(res.telemetry_preserved.get("proto"), "tcp")

    def test_unverified_zeek_flowmeter_routing_to_telemetry_only(self):
        """Zeek flowmeter payload (even with 48 features) is routed to TELEMETRY_ONLY pending parity."""
        res = route_flow(
            self.valid_flow,
            source_channel=TrustedSourceChannel.ZEEK_FLOWMETER,
        )

        self.assertEqual(res.route, RoutingDecision.TELEMETRY_ONLY)
        self.assertFalse(res.is_eligible_for_ml)
        self.assertIsNone(res.feature_vector)
        self.assertIn("parity", res.routing_reason.lower())

    def test_client_source_spoofing_prevented(self):
        """Client-provided source tags in payload are strictly ignored."""
        spoofed_payload = dict(self.valid_flow)
        spoofed_payload["source"] = "PCAP_RECONSTRUCTED"
        spoofed_payload["source_channel"] = "PCAP_RECONSTRUCTED"

        # Backend identifies request as untrusted client or connection logger
        res = route_flow(
            spoofed_payload,
            source_channel=TrustedSourceChannel.UNTRUSTED_CLIENT,
        )

        self.assertEqual(res.route, RoutingDecision.TELEMETRY_ONLY)
        self.assertFalse(res.is_eligible_for_ml)
        self.assertIsNone(res.feature_vector)

    # --------------------------------------------------------------------------
    # 8. Inference Isolation & Zero Fabrication Verification
    # --------------------------------------------------------------------------

    def test_telemetry_only_flows_never_reach_inference_runner(self):
        """safe_route_and_evaluate never calls model predictor for TELEMETRY_ONLY flows."""
        mock_runner = MagicMock()

        # 1. Native connection record
        conn_rec = {"uid": "test1", "proto": "tcp", "id.resp_p": 80}
        out_conn = safe_route_and_evaluate(
            conn_rec,
            source_channel=TrustedSourceChannel.ZEEK_CONN,
            inference_runner=mock_runner,
        )

        mock_runner.assert_not_called()
        self.assertEqual(out_conn["route"], "TELEMETRY_ONLY")
        self.assertFalse(out_conn["ml_classification_performed"])
        self.assertIsNone(out_conn["predicted_family"])
        self.assertIsNone(out_conn["class_confidence"])
        self.assertIsNone(out_conn["risk_score"])
        self.assertIsNone(out_conn["feature_vector"])

        # 2. Incomplete 48-feature flow
        incomplete_flow = dict(self.valid_flow)
        del incomplete_flow["psh_flag_count"]
        out_incomp = safe_route_and_evaluate(
            incomplete_flow,
            source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED,
            inference_runner=mock_runner,
        )

        mock_runner.assert_not_called()
        self.assertEqual(out_incomp["route"], "TELEMETRY_ONLY")
        self.assertFalse(out_incomp["ml_classification_performed"])
        self.assertIsNone(out_incomp["predicted_family"])

    def test_compatible_complete_flow_calls_inference_runner(self):
        """safe_route_and_evaluate calls inference runner when both gates pass."""
        mock_runner = MagicMock(
            return_value={
                "ml_classification_performed": True,
                "predicted_family": "BENIGN",
                "class_confidence": 0.99,
                "raw_decision_score": 0.15,
                "normalized_anomaly_score": 0.05,
                "is_statistical_anomaly": False,
                "risk_score": 10,
                "severity": "LOW",
                "triage_status": "NORMAL",
            }
        )

        out = safe_route_and_evaluate(
            self.valid_flow,
            source_channel=TrustedSourceChannel.PCAP_RECONSTRUCTED,
            inference_runner=mock_runner,
        )

        mock_runner.assert_called_once()
        self.assertEqual(out["route"], "ML_INFERENCE")
        self.assertTrue(out["is_eligible_for_ml"])
        self.assertTrue(out["ml_classification_performed"])
        self.assertEqual(out["predicted_family"], "BENIGN")
        self.assertEqual(out["risk_score"], 10)
        self.assertIsNotNone(out["feature_vector"])

    # --------------------------------------------------------------------------
    # 9. Empirical Evaluation on Real Repository Fixtures
    # --------------------------------------------------------------------------

    def test_empirical_fixture_evaluation_sample_conn_json(self):
        """Empirically evaluate all 15 real records in tests/fixtures/zeek/sample_conn.json."""
        fixture_path = PROJECT_ROOT / "tests" / "fixtures" / "zeek" / "sample_conn.json"
        self.assertTrue(fixture_path.exists(), f"Fixture not found at {fixture_path}")

        records = []
        with open(fixture_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))

        self.assertEqual(len(records), 15, "Expected exactly 15 records in sample_conn.json")

        evaluated_results = []
        completeness_scores = []

        for rec in records:
            res = route_flow(rec, source_channel=TrustedSourceChannel.ZEEK_CONN)
            evaluated_results.append(res)
            completeness_scores.append(res.completeness.completeness_score)

        # Assert empirical metrics across the real fixture
        telemetry_only_count = sum(
            1 for r in evaluated_results if r.route == RoutingDecision.TELEMETRY_ONLY
        )
        ml_eligible_count = sum(1 for r in evaluated_results if r.is_eligible_for_ml)
        max_completeness = max(completeness_scores)

        # 1. 100% of native Zeek records are routed to TELEMETRY_ONLY
        self.assertEqual(telemetry_only_count, 15)

        # 2. Exactly 0 records admitted to ML inference
        self.assertEqual(ml_eligible_count, 0)

        # 3. Maximum completeness is at most 1/48 (<= 0.020834) because conn.log
        #    lacks statistical flow metrics (only destination_port might match if mapped)
        self.assertLessEqual(max_completeness, 0.025)

        # 4. 100% of UIDs are preserved in telemetry
        uids_preserved = [r.telemetry_preserved.get("uid") for r in evaluated_results]
        self.assertEqual(len(uids_preserved), 15)
        self.assertTrue(all(uid is not None for uid in uids_preserved))
        self.assertIn("CHhAvVGS1DHF508n6", uids_preserved)


if __name__ == "__main__":
    unittest.main()
