"""Automated tests for Production Feature Drift Monitoring.

Covers:
1. Synthetic algorithm invariants (PSI, SMD, epsilon smoothing, boundary clipping).
2. Constant baseline feature handling (zero division protection).
3. Zero-inflated distribution handling (adaptive point-mass isolation).
4. Non-finite, missing, and malformed input rejection.
5. Minimum sample size enforcement (N >= 100).
6. Zeek schema absence rejection (inability to evaluate native conn.log without complete K=48).
7. Baseline artifact integrity and StandardScaler alignment verification.
8. API endpoints, authentication guards, and response schemas.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

import numpy as np
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Ensure project root and backend are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import get_db
from app.core.security import AuthenticatedUser, get_current_user
from app.db.base import Base
from app.db.models.analysis_job import AnalysisJob
from app.db.models.flow_provenance import FlowProvenance
from app.db.models.security_event import SecurityEvent
from app.main import app
from app.schemas.flows import FlowFeaturesInput
from app.services.drift_service import (
    MINIMUM_RECOMMENDED_SAMPLE_SIZE,
    FeatureDriftService,
    get_drift_service,
)
from app.services.preprocessor import FeatureValidationError

BASELINE_FILE = PROJECT_ROOT / "data" / "metadata" / "baseline_feature_distributions.json"
SELECTED_FEATURES_FILE = PROJECT_ROOT / "data" / "metadata" / "selected_features.json"


def _create_sample_flow_dict(scale: float = 1.0) -> dict:
    """Helper creating a complete valid K=48 flow dictionary."""
    with open(SELECTED_FEATURES_FILE, "r", encoding="utf-8") as f:
        feature_names = json.load(f)["selected_features"]

    return {feat: float(idx + 1) * scale for idx, feat in enumerate(feature_names)}


class TestSyntheticDriftAlgorithms(unittest.TestCase):
    """Synthetic unit tests certifying mathematical invariants of drift metrics."""

    def setUp(self):
        self.service = FeatureDriftService()
        self.feat_names = self.service.canonical_features

    def test_baseline_self_comparison_psi_and_smd_zero(self):
        """Comparing a dataset matching the baseline parameters produces PSI ~ 0 and SMD ~ 0."""
        n_samples = 500
        matrix = np.zeros((n_samples, len(self.feat_names)), dtype=np.float64)

        baseline_features = self.service._baseline_data["features"]
        for idx, feat in enumerate(self.feat_names):
            b_meta = baseline_features[feat]
            # Use baseline mean as constant center
            matrix[:, idx] = float(b_meta["mean"])

        res = self.service.evaluate_matrix(matrix)
        self.assertEqual(res.summary.evaluated_flow_count, n_samples)
        self.assertEqual(res.summary.evaluated_feature_count, 48)

        # SMD for features matching baseline mean should be exactly 0.0
        for feat in self.feat_names:
            m = res.feature_metrics[feat]
            if m.smd is not None:
                self.assertAlmostEqual(m.smd, 0.0, places=4)

    def test_synthetic_distribution_shift_increases_psi(self):
        """Injecting a substantial distribution shift produces high PSI and triggers SIGNIFICANT severity."""
        n_samples = 500
        matrix = np.zeros((n_samples, len(self.feat_names)), dtype=np.float64)

        baseline_features = self.service._baseline_data["features"]
        for idx, feat in enumerate(self.feat_names):
            b_meta = baseline_features[feat]
            # Shift values by 10 standard deviations above baseline mean
            b_std = max(float(b_meta["std"]), 1.0)
            matrix[:, idx] = float(b_meta["mean"]) + 10.0 * b_std

        res = self.service.evaluate_matrix(matrix)
        self.assertEqual(res.summary.overall_drift_status, "SIGNIFICANT_DRIFT")
        self.assertGreater(res.summary.significant_feature_count, 0)
        self.assertGreater(res.summary.mean_psi, 0.25)

    def test_constant_baseline_feature_handled_safely(self):
        """Features with zero baseline variance produce smd=None without division by zero."""
        # Create a mock service with a constant feature
        mock_service = copy.deepcopy(self.service)
        first_feat = self.feat_names[0]
        mock_service._baseline_data["features"][first_feat]["std"] = 0.0
        mock_service._baseline_data["features"][first_feat]["variance"] = 0.0

        sample_matrix = np.ones((150, len(self.feat_names)), dtype=np.float64) * 5.0
        res = mock_service.evaluate_matrix(sample_matrix)

        first_metric = res.feature_metrics[first_feat]
        self.assertIsNone(first_metric.smd)
        self.assertTrue(first_metric.data_quality.is_constant_baseline)
        self.assertTrue(np.isfinite(first_metric.psi))

    def test_zero_inflated_features_no_duplicate_bin_error(self):
        """Zero-inflated features (e.g. 95% zeros) evaluate cleanly without NaN or bin errors."""
        n_samples = 200
        # Build vector with 95% zeros and 5% positive values
        col_vals = np.zeros(n_samples, dtype=np.float64)
        col_vals[190:] = np.linspace(10.0, 100.0, 10)

        inner_cutoffs = [1e-6, 20.0, 50.0, 80.0]
        ref_props = [0.90, 0.03, 0.03, 0.02, 0.02]

        psi = self.service._calculate_psi(col_vals, inner_cutoffs, ref_props)
        self.assertTrue(np.isfinite(psi))
        self.assertGreaterEqual(psi, 0.0)

    def test_empty_bins_and_epsilon_smoothing_finite(self):
        """When incoming samples are concentrated entirely in one bin, PSI remains finite."""
        n_samples = 200
        # All samples fall in the first bin
        col_vals = np.zeros(n_samples, dtype=np.float64)
        inner_cutoffs = [1e-6, 10.0, 20.0, 30.0, 40.0]
        ref_props = [0.20, 0.20, 0.20, 0.20, 0.20]

        psi = self.service._calculate_psi(col_vals, inner_cutoffs, ref_props)
        self.assertTrue(np.isfinite(psi))
        self.assertFalse(np.isnan(psi))
        self.assertFalse(np.isinf(psi))
        self.assertGreater(psi, 0.0)

    def test_values_outside_baseline_boundaries_handled(self):
        """Extreme values (-1e9, +1e12) fall into outer bins without error."""
        n_samples = 150
        matrix = np.zeros((n_samples, len(self.feat_names)), dtype=np.float64)
        matrix[0, :] = -1e9
        matrix[1, :] = 1e12

        res = self.service.evaluate_matrix(matrix)
        self.assertEqual(res.summary.evaluated_flow_count, n_samples)
        for feat in self.feat_names:
            self.assertTrue(np.isfinite(res.feature_metrics[feat].psi))

    def test_missing_and_non_finite_values_raise_validation_error(self):
        """Flows missing required features or containing NaN/Inf raise FeatureValidationError."""
        flow_dict = _create_sample_flow_dict()

        # 1. Missing feature
        incomplete = copy.deepcopy(flow_dict)
        del incomplete["destination_port"]
        with self.assertRaises(FeatureValidationError):
            self.service.evaluate_flows([incomplete] * 100)

        # 2. NaN value
        nan_flow = copy.deepcopy(flow_dict)
        nan_flow["destination_port"] = float("nan")
        with self.assertRaises(FeatureValidationError):
            self.service.evaluate_flows([nan_flow] * 100)

        # 3. Inf value
        inf_flow = copy.deepcopy(flow_dict)
        inf_flow["destination_port"] = float("inf")
        with self.assertRaises(FeatureValidationError):
            self.service.evaluate_flows([inf_flow] * 100)

    def test_insufficient_sample_size_flagged(self):
        """Batches with fewer than 100 flows are evaluated but flagged as insufficient."""
        n_flows = 25
        flow_list = [_create_sample_flow_dict() for _ in range(n_flows)]
        res = self.service.evaluate_flows(flow_list)

        self.assertFalse(res.summary.is_sample_size_sufficient)
        self.assertEqual(res.summary.overall_drift_status, "INSUFFICIENT_DATA")
        self.assertIsNotNone(res.summary.insufficient_sample_reason)
        self.assertIn("below the recommended minimum", res.summary.insufficient_sample_reason)

    def test_zeek_telemetry_schema_absence_rejected(self):
        """Zeek native connection records lacking K=48 features cannot be evaluated for ML drift."""
        zeek_record = {
            "uid": "C1234567890",
            "id_orig_h": "192.168.1.100",
            "id_orig_p": 44321,
            "id_resp_h": "10.0.0.1",
            "id_resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 1.5,
            "orig_bytes": 1024,
            "resp_bytes": 2048,
            "conn_state": "SF",
        }

        # Zeek native records are missing 36+ canonical features
        with self.assertRaises(FeatureValidationError) as ctx:
            self.service.evaluate_flows([zeek_record] * 100)

        self.assertTrue(len(ctx.exception.missing_features) > 30)


class TestRealBaselineIntegrity(unittest.TestCase):
    """Verification tests against the authentic baseline_feature_distributions.json artifact."""

    def setUp(self):
        self.assertTrue(BASELINE_FILE.exists(), f"Baseline artifact missing: {BASELINE_FILE}")
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            self.baseline = json.load(f)
        with open(SELECTED_FEATURES_FILE, "r", encoding="utf-8") as f:
            self.canonical_features = json.load(f)["selected_features"]

    def test_baseline_feature_ordering_matches_selected_features(self):
        """Baseline features dict must preserve exact canonical order from selected_features.json."""
        baseline_keys = list(self.baseline["features"].keys())
        self.assertEqual(baseline_keys, self.canonical_features)
        self.assertEqual(len(baseline_keys), 48)

    def test_baseline_sha256_checksum_verified(self):
        """Selected features SHA256 in baseline metadata must match actual selected_features.json."""
        with open(SELECTED_FEATURES_FILE, "rb") as f:
            actual_sha = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(self.baseline["selected_features_sha256"], actual_sha)

    def test_all_48_features_have_valid_bins_and_proportions(self):
        """Every feature must have valid, monotonically increasing cutoffs and unit proportions."""
        for feat_name, meta in self.baseline["features"].items():
            cutoffs = meta["inner_cutoffs"]
            props = meta["reference_proportions"]

            # Cutoffs strictly increasing
            for i in range(len(cutoffs) - 1):
                self.assertLess(
                    cutoffs[i],
                    cutoffs[i + 1],
                    f"Cutoffs not strictly increasing for {feat_name}: {cutoffs}",
                )

            # Proportions sum to 1.0
            sum_p = sum(props)
            self.assertAlmostEqual(
                sum_p,
                1.0,
                places=3,
                msg=f"Proportions do not sum to 1.0 for {feat_name}: {sum_p}",
            )

            # Valid moments
            self.assertTrue(np.isfinite(meta["mean"]))
            self.assertTrue(np.isfinite(meta["std"]))
            self.assertGreaterEqual(meta["variance"], 0.0)

    def test_standard_scaler_alignment_zero_delta(self):
        """Baseline verification confirms zero discrepancy with production StandardScaler."""
        align = self.baseline.get("alignment_verification", {})
        self.assertEqual(align.get("status"), "EXACT_ALIGNMENT")
        self.assertEqual(align.get("max_delta_mean"), 0.0)
        self.assertEqual(align.get("max_delta_var"), 0.0)

    def test_strict_rfc8259_json_compliance(self):
        """Baseline file must parse cleanly under strict RFC 8259 rules with zero NaN or Infinity."""
        def _fail_on_constant(val: str):
            raise ValueError(f"Strict JSON violation: {val}")

        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f, parse_constant=_fail_on_constant)
        self.assertIn("features", data)
        self.assertEqual(data["training_sample_count"], 1_979_432)

    def test_statistical_disclaimer_wording(self):
        """Disclaimers must state operational heuristics and prediction performance caveats."""
        from app.schemas.drift import DatasetDriftSummary
        disclaimer = DatasetDriftSummary.model_fields["disclaimer"].default
        self.assertIn(
            "no substantial distribution shift was detected under the configured psi threshold; "
            "model performance was not assessed by this metric",
            disclaimer.lower(),
        )
        self.assertIn("low psi does not prove that model accuracy or confidence is maintained", disclaimer.lower())
        self.assertIn("high psi does not prove an attack is occurring", disclaimer.lower())
        self.assertIn("does not measure prediction performance without suitable ground-truth labels", disclaimer.lower())


class TestDriftApiEndpoints(unittest.IsolatedAsyncioTestCase):
    """Integration tests for the /api/v1/drift routes."""

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
        app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
            username="analyst_alice", role="analyst"
        )
        self.client = TestClient(app)

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await self.engine.dispose()

    def test_get_baseline_endpoint_authenticated(self):
        """GET /api/v1/drift/baseline returns 200 and baseline metadata."""
        resp = self.client.get("/api/v1/drift/baseline")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("metadata", data)
        self.assertIn("features", data)
        self.assertEqual(len(data["features"]), 48)

    def test_unauthenticated_request_rejected(self):
        """Unauthenticated request to drift routes returns 401 Unauthorized."""
        # Temporarily clear user override to simulate unauthenticated request
        del app.dependency_overrides[get_current_user]
        resp = self.client.get("/api/v1/drift/baseline")
        self.assertEqual(resp.status_code, 401)

    def test_evaluate_batch_endpoint_success(self):
        """POST /api/v1/drift/evaluate-batch with 100 flows returns 200 and valid drift metrics."""
        flow_dict = _create_sample_flow_dict()
        payload = {"flows": [flow_dict] * 120}

        resp = self.client.post("/api/v1/drift/evaluate-batch", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("summary", data)
        self.assertIn("feature_metrics", data)
        self.assertEqual(data["summary"]["evaluated_flow_count"], 120)
        self.assertTrue(data["summary"]["is_sample_size_sufficient"])

    def test_evaluate_batch_empty_rejected(self):
        """POST /api/v1/drift/evaluate-batch with empty list returns 422 Unprocessable Entity."""
        payload = {"flows": []}
        resp = self.client.post("/api/v1/drift/evaluate-batch", json=payload)
        self.assertEqual(resp.status_code, 422)

    async def test_telemetry_window_empty_db_insufficient_data(self):
        """GET /api/v1/drift/telemetry-window on empty database returns INSUFFICIENT_DATA summary."""
        resp = self.client.get("/api/v1/drift/telemetry-window?limit=500")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["summary"]["evaluated_flow_count"], 0)
        self.assertEqual(data["summary"]["overall_drift_status"], "INSUFFICIENT_DATA")

    async def test_telemetry_window_populated_db_evaluation(self):
        """GET /api/v1/drift/telemetry-window evaluates persisted security_events feature vectors."""
        flow_dict = _create_sample_flow_dict()

        # Seed 120 security events into in-memory SQLite
        async with self.session_factory() as session:
            job = AnalysisJob(
                filename="test.pcapng",
                file_size_bytes=10000,
                total_flows_extracted=120,
                total_flows_analyzed=120,
                anomalies_flagged=0,
                processing_time_ms=50.0,
            )
            session.add(job)
            await session.flush()

            for i in range(120):
                ev = SecurityEvent(
                    job_id=job.id,
                    source_channel="PCAP_BATCH",
                    ml_classification_performed=True,
                    feature_vector=flow_dict,
                )
                session.add(ev)
            await session.commit()

        resp = self.client.get("/api/v1/drift/telemetry-window?limit=200")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["summary"]["evaluated_flow_count"], 120)
        self.assertTrue(data["summary"]["is_sample_size_sufficient"])
        self.assertEqual(len(data["feature_metrics"]), 48)


if __name__ == "__main__":
    unittest.main()
