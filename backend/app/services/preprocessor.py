"""Inference Preprocessor Service.

Validates flow feature payloads, enforces strict 48/47 feature contracts,
rejects missing or non-finite inputs, and produces aligned numpy feature matrices
with artifact-matched StandardScaler transformations.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

import numpy as np
from app.services.model_registry import ModelArtifactBundle


class FeatureValidationError(ValueError):
    """Raised when flow features fail schema contract, completeness, or numeric validation."""

    def __init__(self, message: str, missing_features: list[str] | None = None, invalid_fields: list[str] | None = None):
        super().__init__(message)
        self.missing_features = missing_features or []
        self.invalid_fields = invalid_fields or []


class InferencePreprocessor:
    """Vectorized preprocessor transforming raw flow dictionaries into model input matrices."""

    @staticmethod
    def validate_and_extract_flow(
        flow_data: Mapping[str, Any],
        required_features: list[str],
    ) -> np.ndarray:
        """Validate a single flow dictionary against required features and return 1D float64 array.

        Raises:
            FeatureValidationError: If any required feature is missing or contains non-finite values.
        """
        missing: list[str] = []
        invalid: list[str] = []
        values: list[float] = []

        for feat in required_features:
            if feat not in flow_data:
                missing.append(feat)
                continue

            raw_val = flow_data[feat]
            if raw_val is None:
                invalid.append(f"{feat}: value is None")
                continue

            try:
                val = float(raw_val)
                if not math.isfinite(val):
                    invalid.append(f"{feat}: non-finite value ({val})")
                else:
                    values.append(val)
            except (ValueError, TypeError):
                invalid.append(f"{feat}: invalid numeric type ({raw_val!r})")

        if missing:
            raise FeatureValidationError(
                f"Missing {len(missing)} required flow feature(s): {missing}",
                missing_features=missing,
            )

        if invalid:
            raise FeatureValidationError(
                f"Invalid values in {len(invalid)} flow feature(s): {invalid}",
                invalid_fields=invalid,
            )

        return np.array(values, dtype=np.float64)

    @classmethod
    def preprocess_single_flow(
        cls,
        flow_data: Mapping[str, Any],
        bundle: ModelArtifactBundle,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Preprocess a single flow dictionary for a specific model bundle.

        Returns:
            (X_raw_2d, X_scaled_2d) — Both are (1, n_features) numpy float64 arrays.
            If bundle does not use a scaler, X_scaled_2d is identical to X_raw_2d.
        """
        x_1d = cls.validate_and_extract_flow(flow_data, bundle.feature_names)
        x_2d = x_1d.reshape(1, -1)

        if bundle.scaler is not None:
            x_scaled = bundle.scaler.transform(x_2d)
        else:
            x_scaled = x_2d

        return x_2d, x_scaled

    @classmethod
    def preprocess_batch_flows(
        cls,
        flows: list[Mapping[str, Any]],
        bundle: ModelArtifactBundle,
        max_batch_size: int = 5000,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Preprocess a batch of flow dictionaries for a specific model bundle.

        Raises:
            FeatureValidationError: If batch is empty, exceeds max_batch_size, or any flow fails validation.

        Returns:
            (X_raw, X_scaled) — Both are (N, n_features) numpy float64 arrays.
        """
        if not flows:
            raise FeatureValidationError("Batch flows list cannot be empty.")

        if len(flows) > max_batch_size:
            raise FeatureValidationError(
                f"Batch size {len(flows)} exceeds maximum allowed limit of {max_batch_size} flows."
            )

        rows = []
        for idx, flow in enumerate(flows):
            try:
                x_1d = cls.validate_and_extract_flow(flow, bundle.feature_names)
                rows.append(x_1d)
            except FeatureValidationError as e:
                raise FeatureValidationError(
                    f"Flow at index {idx} failed validation: {e}",
                    missing_features=e.missing_features,
                    invalid_fields=e.invalid_fields,
                ) from e

        x_raw = np.vstack(rows)

        if bundle.scaler is not None:
            x_scaled = bundle.scaler.transform(x_raw)
        else:
            x_scaled = x_raw

        return x_raw, x_scaled
