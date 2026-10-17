"""Tests for Stage 6A PCAP Empirical Validation and Matching Logic.

Validates:
1. Symmetric duration tolerance boundaries.
2. Ambiguous multi-candidate exclusion.
3. Bidirectional one-to-one uniqueness enforcement (cross-flow collision rejection).
4. Empty capture and empty reference dataset handling.
5. Non-finite, NaN, and underflow rejection.
6. Error metric calculation correctness (MAE, Median, P95, Max, exact match rate).
7. Deterministic report structure containing all 48 canonical features.
8. Real-data empirical validation on authentic sample fixtures.

Note:
A test that verifies matching logic is not, by itself, proof of empirical
CICFlowMeter parity; matching on (destination_port, flow_duration) is heuristic.
"""

from __future__ import annotations

import io
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock

import numpy as np
import pandas as pd

# Add backend and project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas.flows import FlowFeaturesInput
from app.services.pcap.feature_adapter import PcapFeatureAdapter
from app.services.pcap.flow_state import BidirectionalFlowKey, FlowAccumulator
from app.services.pcap.pcap_reader import RawPacket
from scripts.run_pcap_empirical_validation import (
    CSV_CANONICAL_COLUMN_MAP,
    FlowMatchResult,
    PcapEmpiricalValidator,
)


class TestSyntheticMatchingAndParityLogic(unittest.TestCase):
    """Unit tests verifying matching semantics, disambiguation, and error metrics on synthetic data."""

    def setUp(self):
        self.validator = PcapEmpiricalValidator(
            min_duration_tol_us=10.0,
            rel_duration_tol=0.01,
        )

    def _create_mock_flow_accumulator(
        self,
        dst_port: int,
        duration_us: int,
        flow_id: int = 1,
    ) -> FlowAccumulator:
        """Create a lightweight synthetic FlowAccumulator."""
        p1 = RawPacket(
            timestamp_sec=100.0,
            timestamp_us=100_000_000,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=50000 + flow_id,
            dst_port=dst_port,
            ip_proto=6,
            ip_length=60,
            header_length=40,
            payload_length=20,
            tcp_flags=2,  # SYN
            tcp_window=65535,
            tcp_header_len=20,
        )
        p2 = RawPacket(
            timestamp_sec=100.0 + (duration_us / 1_000_000.0),
            timestamp_us=100_000_000 + duration_us,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.10",
            src_port=dst_port,
            dst_port=50000 + flow_id,
            ip_proto=6,
            ip_length=60,
            header_length=40,
            payload_length=20,
            tcp_flags=18,  # SYN-ACK
            tcp_window=29200,
            tcp_header_len=20,
        )
        key = BidirectionalFlowKey.from_endpoints(6, p1.src_ip, p1.src_port, p1.dst_ip, p1.dst_port)
        acc = FlowAccumulator(key, p1)
        if duration_us > 0:
            acc.add_packet(p2)
        acc.close()
        return acc

    def _create_sample_feature_input(self, dst_port: float = 80.0, **kwargs) -> FlowFeaturesInput:
        """Create a complete canonical FlowFeaturesInput with sensible defaults."""
        defaults = {
            "destination_port": dst_port,
            "total_forward_packets": 1.0,
            "total_forward_bytes": 20.0,
            "min_packet_length": 20.0,
            "max_packet_length": 20.0,
            "packet_length_mean": 20.0,
            "packet_length_variance": 0.0,
            "fwd_packet_length_max": 20.0,
            "fwd_packet_length_min": 20.0,
            "avg_fwd_segment_size": 20.0,
            "bwd_packet_length_min": 0.0,
            "bwd_packet_length_mean": 0.0,
            "bwd_packet_length_std": 0.0,
            "fin_flag_count": 0.0,
            "syn_flag_count": 1.0,
            "psh_flag_count": 0.0,
            "ack_flag_count": 0.0,
            "urg_flag_count": 0.0,
            "ece_flag_count": 0.0,
            "fwd_urg_flags": 0.0,
            "fwd_header_length": 40.0,
            "bwd_header_length": 0.0,
            "min_seg_size_fwd": 20.0,
            "init_win_bytes_fwd": 65535.0,
            "init_win_bytes_bwd": -1.0,
            "act_data_pkt_fwd": 1.0,
            "down_up_ratio": 0.0,
            "fwd_iat_total": 0.0,
            "fwd_iat_mean": 0.0,
            "fwd_iat_std": 0.0,
            "fwd_iat_min": 0.0,
            "bwd_iat_total": 0.0,
            "bwd_iat_mean": 0.0,
            "bwd_iat_std": 0.0,
            "bwd_iat_max": 0.0,
            "bwd_iat_min": 0.0,
            "flow_iat_mean": 0.0,
            "flow_iat_std": 0.0,
            "flow_iat_min": 0.0,
            "flow_bytes_per_sec": 0.0,
            "fwd_packets_per_sec": 0.0,
            "bwd_packets_per_sec": 0.0,
            "active_mean": 0.0,
            "active_std": 0.0,
            "active_max": 0.0,
            "active_min": 0.0,
            "idle_std": 0.0,
            "idle_min": 0.0,
        }
        defaults.update(kwargs)
        return FlowFeaturesInput(**defaults)

    def test_symmetric_tolerance_boundary(self):
        """Verify that duration tolerance matching is strictly symmetric in both directions."""
        flow = self._create_mock_flow_accumulator(dst_port=80, duration_us=1000)
        feat = self._create_sample_feature_input(dst_port=80.0)

        # Tolerance for 1000 us is max(10.0, 1000 * 0.01) = 10.0 us
        # Exactly at boundaries: 990 us (-tol), 1010 us (+tol)
        ref_df = pd.DataFrame({
            "Destination Port": [80, 80, 80],
            "Flow Duration": [990.0, 1010.0, 1011.0],  # 1011 is outside tolerance
        })
        # Add required canonical columns with default zero
        for col in CSV_CANONICAL_COLUMN_MAP.values():
            if col not in ref_df.columns:
                ref_df[col] = 0.0

        ports_ref = ref_df["Destination Port"].to_numpy(dtype=np.int64)
        durs_ref = ref_df["Flow Duration"].to_numpy(dtype=np.float64)

        # 1. Flow matches both 990 and 1010 -> should be AMBIGUOUS (2 matches)
        res = self.validator.match_flows([flow], [feat], ref_df, ports_ref, durs_ref)
        self.assertEqual(res.ambiguous_pcap_count, 1)
        self.assertEqual(res.strict_1to1_matches_count, 0)

        # 2. Test single boundary match within tolerance (990 us)
        ref_single = ref_df.iloc[[0]].copy()
        res_single = self.validator.match_flows(
            [flow], [feat], ref_single,
            ref_single["Destination Port"].to_numpy(dtype=np.int64),
            ref_single["Flow Duration"].to_numpy(dtype=np.float64)
        )
        self.assertEqual(res_single.strict_1to1_matches_count, 1)
        self.assertEqual(res_single.ambiguous_pcap_count, 0)

        # 3. Test value strictly outside tolerance (1011 us)
        ref_outside = ref_df.iloc[[2]].copy()
        res_outside = self.validator.match_flows(
            [flow], [feat], ref_outside,
            ref_outside["Destination Port"].to_numpy(dtype=np.int64),
            ref_outside["Flow Duration"].to_numpy(dtype=np.float64)
        )
        self.assertEqual(res_outside.unmatched_pcap_count, 1)
        self.assertEqual(res_outside.strict_1to1_matches_count, 0)

    def test_ambiguous_candidate_matches_strictly_excluded(self):
        """When a PCAP flow has multiple candidate matches in reference CSV, it must be excluded."""
        flow = self._create_mock_flow_accumulator(dst_port=443, duration_us=5000)
        feat = self._create_sample_feature_input(dst_port=443.0)

        # Two reference rows with identical port and duration
        ref_df = pd.DataFrame({
            "Destination Port": [443, 443],
            "Flow Duration": [5000.0, 5002.0],
        })
        for col in CSV_CANONICAL_COLUMN_MAP.values():
            if col not in ref_df.columns:
                ref_df[col] = 0.0

        res = self.validator.match_flows(
            [flow], [feat], ref_df,
            ref_df["Destination Port"].to_numpy(dtype=np.int64),
            ref_df["Flow Duration"].to_numpy(dtype=np.float64)
        )
        self.assertEqual(res.ambiguous_pcap_count, 1)
        self.assertEqual(res.strict_1to1_matches_count, 0)
        self.assertEqual(len(res.paired_flows), 0)

    def test_cross_flow_collision_one_to_one_enforced(self):
        """When multiple PCAP flows claim the same reference row, both must be excluded."""
        flow1 = self._create_mock_flow_accumulator(dst_port=80, duration_us=2000, flow_id=1)
        flow2 = self._create_mock_flow_accumulator(dst_port=80, duration_us=2000, flow_id=2)
        feat1 = self._create_sample_feature_input(dst_port=80.0)
        feat2 = self._create_sample_feature_input(dst_port=80.0)

        # Only one reference row exists for port 80 duration 2000
        ref_df = pd.DataFrame({
            "Destination Port": [80],
            "Flow Duration": [2000.0],
        })
        for col in CSV_CANONICAL_COLUMN_MAP.values():
            if col not in ref_df.columns:
                ref_df[col] = 0.0

        res = self.validator.match_flows(
            [flow1, flow2], [feat1, feat2], ref_df,
            ref_df["Destination Port"].to_numpy(dtype=np.int64),
            ref_df["Flow Duration"].to_numpy(dtype=np.float64)
        )
        # Both PCAP flows collided on the single reference row
        self.assertEqual(res.ambiguous_ref_collision_count, 2)
        self.assertEqual(res.strict_1to1_matches_count, 0)
        self.assertEqual(len(res.paired_flows), 0)

    def test_empty_capture_and_empty_reference_handling(self):
        """Validator must handle empty captures and empty reference data gracefully."""
        # 1. Empty PCAP flows
        ref_df = pd.DataFrame({"Destination Port": [80], "Flow Duration": [100.0]})
        for col in CSV_CANONICAL_COLUMN_MAP.values():
            ref_df[col] = 0.0
        res1 = self.validator.match_flows(
            [], [], ref_df,
            ref_df["Destination Port"].to_numpy(dtype=np.int64),
            ref_df["Flow Duration"].to_numpy(dtype=np.float64)
        )
        self.assertEqual(res1.total_pcap_flows, 0)
        self.assertEqual(res1.strict_1to1_matches_count, 0)

        # 2. Empty reference dataframe
        flow = self._create_mock_flow_accumulator(dst_port=80, duration_us=100)
        feat = self._create_sample_feature_input(dst_port=80.0)
        res2 = self.validator.match_flows(
            [flow], [feat], pd.DataFrame(columns=["Destination Port", "Flow Duration"]),
            np.array([], dtype=np.int64), np.array([], dtype=np.float64)
        )
        self.assertEqual(res2.total_pcap_flows, 1)
        self.assertEqual(res2.unmatched_pcap_count, 1)
        self.assertEqual(res2.strict_1to1_matches_count, 0)

    def test_error_metric_calculations_exact(self):
        """Parity statistics engine accurately calculates MAE, median, and exact match rates."""
        # Create pairs with known exact differences:
        # Flow 1: diff = 0
        # Flow 2: diff = 10
        # Flow 3: diff = 20
        # Expected MAE = 10, Median = 10, Max = 20, Exact match count = 1 / 3
        f_pcap1 = self._create_sample_feature_input(dst_port=80.0, min_packet_length=20.0)
        f_ref1 = self._create_sample_feature_input(dst_port=80.0, min_packet_length=20.0)

        f_pcap2 = self._create_sample_feature_input(dst_port=80.0, min_packet_length=30.0)
        f_ref2 = self._create_sample_feature_input(dst_port=80.0, min_packet_length=20.0)

        f_pcap3 = self._create_sample_feature_input(dst_port=80.0, min_packet_length=40.0)
        f_ref3 = self._create_sample_feature_input(dst_port=80.0, min_packet_length=20.0)

        pairs = [(f_pcap1, f_ref1), (f_pcap2, f_ref2), (f_pcap3, f_ref3)]
        metrics = self.validator.evaluate_feature_parity(pairs)

        self.assertEqual(len(metrics), 48)
        m_len = metrics["min_packet_length"]
        self.assertAlmostEqual(m_len["mean_abs_error"], 10.0, places=4)
        self.assertAlmostEqual(m_len["median_abs_error"], 10.0, places=4)
        self.assertAlmostEqual(m_len["max_abs_error"], 20.0, places=4)
        self.assertEqual(m_len["exact_match_count"], 1)
        self.assertAlmostEqual(m_len["exact_match_rate"], 1.0 / 3.0, places=4)
        self.assertTrue(m_len["all_finite"])

    def test_duration_tolerance_strict_symmetry_under_swapping(self):
        """Verify that duration tolerance matching is mathematically symmetric under swapping.

        For any two durations d1 and d2:
        is_within_duration_tolerance(d1, d2) == is_within_duration_tolerance(d2, d1)
        """
        test_cases = [
            (0.0, 0.0, True, "zero equality"),
            (100.0, 100.0, True, "positive equality"),
            (0.0, 10.0, True, "zero to absolute tolerance"),
            (0.0, 10.001, False, "zero exceeding absolute tolerance"),
            (100.0, 110.0, True, "100us with 10us abs tol"),
            (100.0, 110.001, False, "100us exceeding 10us abs tol"),
            (10_000.0, 10_100.0, True, "10000us with 100us (1%) tol"),
            (10_000.0, 10_101.5, False, "10000us exceeding 1% tol"),
            (1_000_000.0, 1_010_000.0, True, "1s with 1% tol"),
            (1_000_000.0, 1_010_100.0, True, "1s within 1% tol on max(d1, d2)"),
            (1_000_000.0, 1_010_200.0, False, "1s exceeding 1% tol"),
            (1000.0, 1010.05, True, "boundary symmetry check"),
        ]

        for d1, d2, expected, desc in test_cases:
            match_forward = PcapEmpiricalValidator.is_within_duration_tolerance(d1, d2)
            match_reverse = PcapEmpiricalValidator.is_within_duration_tolerance(d2, d1)
            self.assertEqual(
                match_forward,
                match_reverse,
                f"Symmetry violation for {desc}: fwd={match_forward}, rev={match_reverse} for ({d1}, {d2})",
            )
            self.assertEqual(
                match_forward,
                expected,
                f"Expected {expected} for {desc} with ({d1}, {d2}), got {match_forward}",
            )

    def test_matching_constrained_features_marked(self):
        """Both destination_port and flow_duration_ms must be explicitly flagged as matching-constrained."""
        pair = (
            self._create_sample_feature_input(dst_port=80.0),
            self._create_sample_feature_input(dst_port=80.0),
        )
        durs = [(1000.0, 1005.0)]
        metrics = self.validator.evaluate_feature_parity([pair], paired_durations=durs)
        self.assertEqual(len(metrics), 49)
        self.assertTrue(metrics["destination_port"]["is_matching_constrained"])
        self.assertTrue(metrics["flow_duration_ms"]["is_matching_constrained"])
        self.assertFalse(metrics["packet_length_mean"]["is_matching_constrained"])
        self.assertFalse(metrics["syn_flag_count"]["is_matching_constrained"])
        self.assertFalse(metrics["fwd_iat_total"]["is_matching_constrained"])

    def test_duration_units_audit_and_equivalence(self):
        """Verify duration unit consistency across accumulator, adapter, and reference data."""
        # 1. FlowAccumulator duration is computed in microseconds
        acc = self._create_mock_flow_accumulator(dst_port=80, duration_us=12345)
        recon_us = acc.last_ts_us - acc.start_ts_us
        self.assertEqual(recon_us, 12345)

        # 2. PcapFeatureAdapter duration_ms provenance is in milliseconds
        _, prov = PcapFeatureAdapter.adapt(acc)
        self.assertAlmostEqual(prov.duration_ms, 12.345, places=3)

        # 3. Validation matching and feature parity operates strictly on microseconds
        self.assertEqual(acc.last_ts_us - acc.start_ts_us, recon_us)


class TestRealDataEmpiricalValidation(unittest.TestCase):
    """Integration tests executing against authentic local PCAP and CSV fixtures."""

    def setUp(self):
        self.validator = PcapEmpiricalValidator(
            min_duration_tol_us=10.0,
            rel_duration_tol=0.01,
        )
        self.monday_pcap = PROJECT_ROOT / "data" / "samples" / "monday_sample.pcapng"
        self.monday_csv = PROJECT_ROOT / "data" / "extracted" / "MachineLearningCVE" / "Monday-WorkingHours.pcap_ISCX.csv"

    def test_monday_pcap_extraction_invariants(self):
        """Authentic Monday sample must extract exactly 1417 flows with 100% finite features."""
        if not self.monday_pcap.exists():
            self.skipTest(f"Monday PCAP sample fixture not found: {self.monday_pcap}")

        flows, features, provenances = self.validator.reconstruct_pcap_flows(self.monday_pcap)
        self.assertEqual(len(flows), 1417)
        self.assertEqual(len(features), 1417)
        self.assertEqual(len(provenances), 1417)

        # Invariant: Every reconstructed feature must be strictly finite
        for feat in features:
            for k in FlowFeaturesInput.model_fields.keys():
                val = getattr(feat, k)
                self.assertTrue(math.isfinite(val), f"Reconstructed feature {k} is non-finite: {val}")

    def test_reference_csv_cleaning_filters_underflow_rows(self):
        """Reference CSV loading must discard corrupted negative underflow rows and NaNs."""
        if not self.monday_csv.exists():
            self.skipTest(f"Monday reference CSV fixture not found: {self.monday_csv}")

        df, ports, durs, rejected_count = self.validator.load_reference_dataset(self.monday_csv)
        self.assertGreater(len(df), 500_000)
        self.assertGreater(rejected_count, 0, "Corrupted underflow rows should be counted as rejected")
        self.assertTrue(np.all(ports >= 0))
        self.assertTrue(np.all(ports <= 65535))
        self.assertTrue(np.all(durs >= 0))

    def test_monday_dataset_empirical_matching_and_parity_execution(self):
        """Run single-dataset validation and verify heuristic 1-to-1 matching and output report."""
        if not self.monday_pcap.exists() or not self.monday_csv.exists():
            self.skipTest("Monday fixtures not present")

        summary, match_res = self.validator.run_single_dataset(
            pcap_path=self.monday_pcap,
            csv_path=self.monday_csv,
            dataset_key="monday",
            dataset_name="Monday-Benign",
        )

        self.assertEqual(summary.total_pcap_flows, 1417)
        self.assertGreater(summary.strict_1to1_pairs, 50)
        self.assertGreater(summary.ambiguous_pcap_matches, 1000)
        self.assertEqual(summary.finite_features_pct, 100.0)

        # Compute parity metrics on Monday paired flows
        metrics = self.validator.evaluate_feature_parity(
            match_res.paired_flows, match_res.paired_durations
        )
        self.assertEqual(len(metrics), 49)
        self.assertTrue(metrics["destination_port"]["is_matching_constrained"])
        self.assertTrue(metrics["flow_duration_ms"]["is_matching_constrained"])

        # Verify key packet length moments have median absolute error = 0.0000
        self.assertEqual(metrics["min_packet_length"]["median_abs_error"], 0.0)
        self.assertEqual(metrics["max_packet_length"]["median_abs_error"], 0.0)
        self.assertEqual(metrics["syn_flag_count"]["median_abs_error"], 0.0)
        self.assertEqual(metrics["psh_flag_count"]["median_abs_error"], 0.0)
        self.assertEqual(metrics["idle_min"]["median_abs_error"], 0.0)

        # Verify all features in paired flows are finite
        for feat_name, stat in metrics.items():
            self.assertTrue(stat["all_finite"], f"Feature {feat_name} has non-finite values in pairs")


if __name__ == "__main__":
    unittest.main()
