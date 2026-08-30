"""Unit tests for InferencePreprocessor service."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np

# Ensure backend is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.model_registry import get_model_registry
from app.services.preprocessor import (
    FeatureValidationError,
    InferencePreprocessor,
)


def make_valid_48_flow_dict() -> dict[str, float]:
    """Helper to generate a valid 48-feature synthetic flow dictionary."""
    registry = get_model_registry()
    bundle = registry.get_default_supervised_model()
    return {feat: 10.0 for feat in bundle.feature_names}


class PreprocessorTests(unittest.TestCase):
    """Test suite for InferencePreprocessor validation and matrix generation."""

    def setUp(self) -> None:
        self.registry = get_model_registry()
        self.sup_k48 = self.registry.get_default_supervised_model()
        self.anom_k48 = self.registry.get_default_anomaly_model()
        self.sup_k47 = self.registry.get_model("protocol_a_xgboost_k47")
        self.lr_k48 = self.registry.get_model("protocol_a_logisticregression_k48")

    def test_valid_single_flow_preprocessing(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        x_raw, x_scaled = InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k48)
        self.assertEqual(x_raw.shape, (1, 48))
        self.assertEqual(x_scaled.shape, (1, 48))
        self.assertEqual(x_raw.dtype, np.float64)

    def test_missing_feature_raises_error_with_names(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        del flow_dict["destination_port"]
        del flow_dict["total_forward_packets"]

        with self.assertRaises(FeatureValidationError) as ctx:
            InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k48)

        self.assertIn("destination_port", ctx.exception.missing_features)
        self.assertIn("total_forward_packets", ctx.exception.missing_features)
        self.assertEqual(len(ctx.exception.missing_features), 2)

    def test_nan_value_rejected(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        flow_dict["packet_length_mean"] = float("nan")

        with self.assertRaises(FeatureValidationError) as ctx:
            InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k48)

        self.assertTrue(any("packet_length_mean" in f for f in ctx.exception.invalid_fields))

    def test_infinite_value_rejected(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        flow_dict["flow_bytes_per_sec"] = float("inf")

        with self.assertRaises(FeatureValidationError) as ctx:
            InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k48)

        self.assertTrue(any("flow_bytes_per_sec" in f for f in ctx.exception.invalid_fields))

    def test_non_numeric_type_rejected(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        flow_dict["destination_port"] = "invalid_string"  # type: ignore

        with self.assertRaises(FeatureValidationError):
            InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k48)

    def test_k47_port_ablated_preprocessing(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        # Even if destination_port is present or absent, k47 model only requires 47 features
        x_raw, x_scaled = InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k47)
        self.assertEqual(x_raw.shape, (1, 47))
        self.assertEqual(x_scaled.shape, (1, 47))

    def test_scaling_transformation_applied_for_scaler_models(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        # Logistic regression has a fitted StandardScaler
        x_raw, x_scaled = InferencePreprocessor.preprocess_single_flow(flow_dict, self.lr_k48)
        self.assertFalse(np.array_equal(x_raw, x_scaled))

        # XGBoost has no scaler (scaler is None) -> x_raw is x_scaled
        x_raw_xgb, x_scaled_xgb = InferencePreprocessor.preprocess_single_flow(flow_dict, self.sup_k48)
        self.assertTrue(np.array_equal(x_raw_xgb, x_scaled_xgb))

    def test_batch_preprocessing(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        batch = [flow_dict.copy() for _ in range(5)]
        x_raw, x_scaled = InferencePreprocessor.preprocess_batch_flows(batch, self.sup_k48)
        self.assertEqual(x_raw.shape, (5, 48))
        self.assertEqual(x_scaled.shape, (5, 48))

    def test_batch_empty_rejected(self) -> None:
        with self.assertRaises(FeatureValidationError):
            InferencePreprocessor.preprocess_batch_flows([], self.sup_k48)

    def test_batch_limit_exceeded_rejected(self) -> None:
        flow_dict = make_valid_48_flow_dict()
        oversized_batch = [flow_dict.copy() for _ in range(5001)]
        with self.assertRaises(FeatureValidationError):
            InferencePreprocessor.preprocess_batch_flows(oversized_batch, self.sup_k48, max_batch_size=5000)


if __name__ == "__main__":
    unittest.main()
