"""Unit tests for ModelRegistry service."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.domain import DeploymentTier, ModelProtocol, ModelRole
from app.services.model_registry import (
    DEFAULT_ANOMALY_MODEL_KEY,
    DEFAULT_SUPERVISED_MODEL_KEY,
    ModelRegistry,
    compute_file_sha256,
    get_model_registry,
)


class ModelRegistryTests(unittest.TestCase):
    """Test suite for Model Registry loading, metadata, and security."""

    def setUp(self) -> None:
        self.registry = get_model_registry()

    def test_default_supervised_model_loading(self) -> None:
        bundle = self.registry.get_default_supervised_model()
        self.assertEqual(bundle.key, DEFAULT_SUPERVISED_MODEL_KEY)
        self.assertEqual(bundle.protocol, ModelProtocol.PROTOCOL_A)
        self.assertEqual(bundle.feature_set, "K48")
        self.assertEqual(len(bundle.feature_names), 48)
        self.assertEqual(bundle.model_role, ModelRole.SUPERVISED_CLASSIFIER)
        self.assertEqual(bundle.deployment_tier, DeploymentTier.PRODUCTION_DEFAULT)
        self.assertTrue(len(bundle.class_names) >= 8)
        self.assertIsNotNone(bundle.artifact_sha256)
        self.assertEqual(len(bundle.artifact_sha256), 64)

    def test_default_anomaly_model_loading(self) -> None:
        bundle = self.registry.get_default_anomaly_model()
        self.assertEqual(bundle.key, DEFAULT_ANOMALY_MODEL_KEY)
        self.assertEqual(bundle.protocol, ModelProtocol.PROTOCOL_A)
        self.assertEqual(bundle.feature_set, "K48")
        self.assertEqual(len(bundle.feature_names), 48)
        self.assertEqual(bundle.model_role, ModelRole.STATISTICAL_ANOMALY_DETECTOR)
        self.assertIsNotNone(bundle.thresholds)
        self.assertIn(0.01, bundle.thresholds)
        self.assertIn(0.05, bundle.thresholds)

    def test_port_ablated_model_loading(self) -> None:
        bundle = self.registry.get_model("protocol_a_xgboost_k47")
        self.assertEqual(bundle.feature_set, "K47")
        self.assertEqual(len(bundle.feature_names), 47)
        self.assertNotIn("destination_port", bundle.feature_names)

    def test_unknown_model_key_rejected(self) -> None:
        with self.assertRaises(KeyError):
            self.registry.get_model("malicious_unregistered_model_path")

    def test_client_cannot_pass_filesystem_paths(self) -> None:
        with self.assertRaises(KeyError):
            self.registry.get_model("../../../etc/passwd")

    def test_caching_and_reload_consistency(self) -> None:
        # Load first instance
        bundle1 = self.registry.get_model("protocol_a_xgboost_k48")
        dummy_input = np.ones((1, 48), dtype=np.float64)
        pred1 = bundle1.model.predict_proba(dummy_input)

        # Clear cache and reload
        self.registry.clear_cache()
        bundle2 = self.registry.get_model("protocol_a_xgboost_k48")
        pred2 = bundle2.model.predict_proba(dummy_input)

        # Verify exact prediction consistency after reload
        np.testing.assert_allclose(pred1, pred2, rtol=1e-7, atol=1e-7)

    def test_model_summary_metadata(self) -> None:
        bundle = self.registry.get_default_supervised_model()
        summary = bundle.to_summary()
        self.assertEqual(summary.model_key, "protocol_a_xgboost_k48")
        self.assertEqual(summary.n_features, 48)
        self.assertGreater(summary.artifact_size_bytes, 0)
        self.assertEqual(len(summary.artifact_sha256), 64)


if __name__ == "__main__":
    unittest.main()
