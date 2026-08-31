"""Model Registry Service.

Thread-safe loading, caching, integrity verification, and metadata inspection
for versioned ML model artifacts.

Strict Role Separation:
- Protocol A models are production-tier classifiers and anomaly detectors.
- Protocol B models are explicitly tagged for research / cross-capture evaluation.
- Client-provided filesystem paths are strictly prohibited; models are resolved
  exclusively by validated catalog identifiers from the artifacts directory.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
from app.domain import DeploymentTier, ModelProtocol, ModelRole

logger = logging.getLogger(__name__)

# Base path resolution: 3 levels up from backend/app/services -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = PROJECT_ROOT / "artifacts" / "models"


@dataclass(frozen=True)
class ModelMetadataSummary:
    model_key: str
    model_name: str
    protocol: ModelProtocol
    feature_set: str
    n_features: int
    model_role: ModelRole
    deployment_tier: DeploymentTier
    class_names: list[str]
    thresholds: dict[str, float] | None
    training_rows: int | None
    training_time_seconds: float | None
    artifact_size_bytes: int
    artifact_sha256: str
    scaling_applied: bool


@dataclass
class ModelArtifactBundle:
    key: str
    model_name: str
    protocol: ModelProtocol
    feature_set: str
    model_role: ModelRole
    deployment_tier: DeploymentTier
    model: Any
    scaler: Any | None
    label_encoder: Any | None
    feature_names: list[str]
    class_names: list[str]
    thresholds: dict[float, float] | None
    artifact_path: Path
    artifact_sha256: str
    metadata: dict[str, Any]

    def to_summary(self) -> ModelMetadataSummary:
        return ModelMetadataSummary(
            model_key=self.key,
            model_name=self.model_name,
            protocol=self.protocol,
            feature_set=self.feature_set,
            n_features=len(self.feature_names),
            model_role=self.model_role,
            deployment_tier=self.deployment_tier,
            class_names=list(self.class_names),
            thresholds=(
                {str(k): round(v, 6) for k, v in self.thresholds.items()}
                if self.thresholds
                else None
            ),
            training_rows=self.metadata.get("training_rows"),
            training_time_seconds=self.metadata.get("training_time_seconds"),
            artifact_size_bytes=self.metadata.get("artifact_size_bytes", self.artifact_path.stat().st_size if self.artifact_path.exists() else 0),
            artifact_sha256=self.artifact_sha256,
            scaling_applied=self.scaler is not None or self.metadata.get("scaling_applied", False),
        )


# Canonical Catalog of Allowed Model Artifacts
KNOWN_MODEL_CATALOG: dict[str, dict[str, Any]] = {
    # --- Protocol A Production Models (Primary K=48) ---
    "protocol_a_xgboost_k48": {
        "filename": "protocol_a_xgboost_k48.joblib",
        "model_name": "XGBoost",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K48",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.PRODUCTION_DEFAULT,
        "expected_sha256": "7d9b78ff493f4ab0588022aeaef35bb02fd328751f52eb02e79ae7c488f50b89",
    },
    "protocol_a_randomforest_k48": {
        "filename": "protocol_a_randomforest_k48.joblib",
        "model_name": "RandomForest",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K48",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.PRODUCTION_ALTERNATIVE,
        "expected_sha256": "293208aea5217727b08731892e9863729e8ef4ca9e463658c3a6cab58478b8df",
    },
    "protocol_a_logisticregression_k48": {
        "filename": "protocol_a_logisticregression_k48.joblib",
        "model_name": "LogisticRegression",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K48",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.PRODUCTION_ALTERNATIVE,
        "expected_sha256": "4df93d13a8433355318e1b39148fdd4b6bf5f7ffee4402522939ee79503a94c8",
    },
    "protocol_a_isolationforest_k48": {
        "filename": "protocol_a_isolationforest_k48.joblib",
        "model_name": "IsolationForest",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K48",
        "model_role": ModelRole.STATISTICAL_ANOMALY_DETECTOR,
        "deployment_tier": DeploymentTier.PRODUCTION_DEFAULT,
        "expected_sha256": "92cd85d0ece2f5a66df5442046ce9487f14551eaa9ee620d2e106132b880ad30",
    },
    # --- Protocol A Port-Ablated Models (K=47) ---
    "protocol_a_xgboost_k47": {
        "filename": "protocol_a_xgboost_k47.joblib",
        "model_name": "XGBoost",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K47",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.PRODUCTION_ALTERNATIVE,
        "expected_sha256": "f2d014e7e0722168b6290e8ec594da672d53c13a8479565cbaeed8c11c708cf9",
    },
    "protocol_a_randomforest_k47": {
        "filename": "protocol_a_randomforest_k47.joblib",
        "model_name": "RandomForest",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K47",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.PRODUCTION_ALTERNATIVE,
        "expected_sha256": "0932ef8996a9bd6cba08830fe713b47e445321af93a913bc97e93c26ccd881c3",
    },
    "protocol_a_logisticregression_k47": {
        "filename": "protocol_a_logisticregression_k47.joblib",
        "model_name": "LogisticRegression",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K47",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.PRODUCTION_ALTERNATIVE,
        "expected_sha256": "d332d894e042421fd329bcd0244910374acb3cbad900917dfc666f7ac2a55bb4",
    },
    "protocol_a_isolationforest_k47": {
        "filename": "protocol_a_isolationforest_k47.joblib",
        "model_name": "IsolationForest",
        "protocol": ModelProtocol.PROTOCOL_A,
        "feature_set": "K47",
        "model_role": ModelRole.STATISTICAL_ANOMALY_DETECTOR,
        "deployment_tier": DeploymentTier.PRODUCTION_ALTERNATIVE,
        "expected_sha256": "86557c466cbaf2f9b70579f4f964b69b1e11efefdb7e38fab045586f023081a5",
    },
    # --- Protocol B Cross-Capture Evaluation Models (Research Tier) ---
    "protocol_b_xgboost_k48": {
        "filename": "protocol_b_xgboost_k48.joblib",
        "model_name": "XGBoost",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K48",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "875c075e367abdf05652615198ac1f82e5dbb45c7c97feb8992bf7c32cbbae7a",
    },
    "protocol_b_randomforest_k48": {
        "filename": "protocol_b_randomforest_k48.joblib",
        "model_name": "RandomForest",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K48",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "06367c1ed492d361702232b09c62491c77a211cb39dc485275b3252ea68f70fb",
    },
    "protocol_b_logisticregression_k48": {
        "filename": "protocol_b_logisticregression_k48.joblib",
        "model_name": "LogisticRegression",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K48",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "0d4b5310906d945f9bf3c7fa9c0dd650a8c1229aec823cb6d301e5b6dcbb24d8",
    },
    "protocol_b_isolationforest_k48": {
        "filename": "protocol_b_isolationforest_k48.joblib",
        "model_name": "IsolationForest",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K48",
        "model_role": ModelRole.STATISTICAL_ANOMALY_DETECTOR,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "ad72b189c1447dc4ecdb4f05c8b0bc16ee80ad4e5bcc90bce5d5200d7c4fadb8",
    },
    "protocol_b_xgboost_k47": {
        "filename": "protocol_b_xgboost_k47.joblib",
        "model_name": "XGBoost",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K47",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "c1e24c5af52ac6a27552366200d69c0d0622ec2d4fa62e1885fce1a8708f22b6",
    },
    "protocol_b_randomforest_k47": {
        "filename": "protocol_b_randomforest_k47.joblib",
        "model_name": "RandomForest",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K47",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "7313e5311e6797aa9b085fb491e2b3ded3486dc53fc8a93a64acaea62bec7b4c",
    },
    "protocol_b_logisticregression_k47": {
        "filename": "protocol_b_logisticregression_k47.joblib",
        "model_name": "LogisticRegression",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K47",
        "model_role": ModelRole.SUPERVISED_CLASSIFIER,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "cf0558a184a5b7deb872169176dcaececdc6fbdc44b8a19e48b74d207dee802d",
    },
    "protocol_b_isolationforest_k47": {
        "filename": "protocol_b_isolationforest_k47.joblib",
        "model_name": "IsolationForest",
        "protocol": ModelProtocol.PROTOCOL_B,
        "feature_set": "K47",
        "model_role": ModelRole.STATISTICAL_ANOMALY_DETECTOR,
        "deployment_tier": DeploymentTier.RESEARCH_EVALUATION,
        "expected_sha256": "61e3ac8e1211bab062720de35e5de0b680a7b0889fde03f030a04117dd1b4eec",
    },
}

DEFAULT_SUPERVISED_MODEL_KEY = "protocol_a_xgboost_k48"
DEFAULT_ANOMALY_MODEL_KEY = "protocol_a_isolationforest_k48"


def compute_file_sha256(filepath: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


class ModelRegistry:
    """Thread-safe Model Registry managing artifact loading and caching."""

    def __init__(self, models_dir: Path = MODELS_DIR):
        self._models_dir = models_dir
        self._cache: dict[str, ModelArtifactBundle] = {}
        self._lock = threading.Lock()

    @property
    def models_dir(self) -> Path:
        return self._models_dir

    def get_model(self, model_key: str) -> ModelArtifactBundle:
        """Retrieve or load a model bundle by canonical catalog key.

        Raises:
            KeyError: If model_key is not in the known catalog.
            FileNotFoundError: If the artifact file does not exist on disk.
            ValueError: If artifact contents are invalid.
        """
        normalized_key = model_key.strip().lower()
        if normalized_key not in KNOWN_MODEL_CATALOG:
            allowed = sorted(KNOWN_MODEL_CATALOG.keys())
            raise KeyError(
                f"Unknown model key '{model_key}'. Allowed catalog keys: {allowed}"
            )

        with self._lock:
            if normalized_key in self._cache:
                return self._cache[normalized_key]

            bundle = self._load_artifact(normalized_key)
            self._cache[normalized_key] = bundle
            return bundle

    def get_default_supervised_model(self) -> ModelArtifactBundle:
        """Get the default production supervised classifier (Protocol A XGBoost K48)."""
        return self.get_model(DEFAULT_SUPERVISED_MODEL_KEY)

    def get_default_anomaly_model(self) -> ModelArtifactBundle:
        """Get the default production statistical anomaly detector (Protocol A IF K48)."""
        return self.get_model(DEFAULT_ANOMALY_MODEL_KEY)

    def list_models(self) -> list[ModelMetadataSummary]:
        """List all models in catalog with metadata and load status."""
        summaries: list[ModelMetadataSummary] = []
        for key in sorted(KNOWN_MODEL_CATALOG.keys()):
            try:
                bundle = self.get_model(key)
                summaries.append(bundle.to_summary())
            except Exception as e:
                logger.warning(f"Could not load metadata for model '{key}': {e}")
                cat = KNOWN_MODEL_CATALOG[key]
                artifact_path = self._models_dir / cat["filename"]
                summaries.append(
                    ModelMetadataSummary(
                        model_key=key,
                        model_name=cat["model_name"],
                        protocol=cat["protocol"],
                        feature_set=cat["feature_set"],
                        n_features=48 if cat["feature_set"] == "K48" else 47,
                        model_role=cat["model_role"],
                        deployment_tier=cat["deployment_tier"],
                        class_names=[],
                        thresholds=None,
                        training_rows=None,
                        training_time_seconds=None,
                        artifact_size_bytes=artifact_path.stat().st_size if artifact_path.exists() else 0,
                        artifact_sha256=compute_file_sha256(artifact_path) if artifact_path.exists() else "UNAVAILABLE",
                        scaling_applied=False,
                    )
                )
        return summaries

    def clear_cache(self) -> None:
        """Clear cached models (useful for testing or reloading)."""
        with self._lock:
            self._cache.clear()
            logger.info("Model registry cache cleared.")

    def _load_artifact(self, key: str) -> ModelArtifactBundle:
        """Internal helper to load and validate a .joblib artifact bundle."""
        catalog_entry = KNOWN_MODEL_CATALOG[key]
        filename = catalog_entry["filename"]
        artifact_path = self._models_dir / filename

        if not artifact_path.exists():
            raise FileNotFoundError(
                f"Model artifact '{filename}' not found at {artifact_path}."
            )

        logger.info(f"Loading model artifact from {artifact_path}...")
        raw_data = joblib.load(artifact_path)

        if not isinstance(raw_data, dict) or "model" not in raw_data:
            raise ValueError(
                f"Invalid model artifact structure at {artifact_path}. Expected dict with 'model'."
            )

        metadata = raw_data.get("metadata", {})
        feature_names = metadata.get("feature_names", [])
        class_names = metadata.get("class_names", [])
        thresholds = metadata.get("thresholds", None)
        scaler = raw_data.get("scaler", None)
        label_encoder = raw_data.get("label_encoder", None)

        if not feature_names:
            raise ValueError(
                f"Model artifact '{key}' is missing required 'feature_names' in metadata."
            )

        sha256 = compute_file_sha256(artifact_path)
        expected_sha = catalog_entry.get("expected_sha256")
        if expected_sha and sha256.lower() != expected_sha.lower():
            err_msg = (
                f"Model integrity check FAILED for '{key}' ({filename})! "
                f"Expected SHA-256 {expected_sha}, computed {sha256}."
            )
            logger.critical(err_msg)
            raise RuntimeError(err_msg)

        return ModelArtifactBundle(
            key=key,
            model_name=catalog_entry["model_name"],
            protocol=catalog_entry["protocol"],
            feature_set=catalog_entry["feature_set"],
            model_role=catalog_entry["model_role"],
            deployment_tier=catalog_entry["deployment_tier"],
            model=raw_data["model"],
            scaler=scaler,
            label_encoder=label_encoder,
            feature_names=feature_names,
            class_names=class_names,
            thresholds=thresholds,
            artifact_path=artifact_path,
            artifact_sha256=sha256,
            metadata=metadata,
        )

    def validate_required_models_exist(self) -> dict[str, str]:
        """Verify presence and SHA-256 integrity of default production models.

        Returns:
            dict mapping required model key to verified SHA-256 hash.

        Raises:
            FileNotFoundError: If a required model artifact is missing.
            RuntimeError: If a required model artifact fails checksum verification.
        """
        required_keys = [DEFAULT_SUPERVISED_MODEL_KEY, DEFAULT_ANOMALY_MODEL_KEY]
        verified: dict[str, str] = {}
        for key in required_keys:
            cat = KNOWN_MODEL_CATALOG[key]
            path = self._models_dir / cat["filename"]
            if not path.exists():
                raise FileNotFoundError(
                    f"CRITICAL: Required production model artifact '{cat['filename']}' "
                    f"not found at {path}. Please bind-mount or provision the frozen Stage 3 "
                    f"model artifacts under artifacts/models/."
                )
            actual_sha = compute_file_sha256(path)
            expected_sha = cat.get("expected_sha256")
            if expected_sha and actual_sha.lower() != expected_sha.lower():
                raise RuntimeError(
                    f"CRITICAL: Model integrity check FAILED for required model '{key}' ({cat['filename']})! "
                    f"Expected SHA-256 {expected_sha}, got {actual_sha}."
                )
            verified[key] = actual_sha
        return verified


# Global singleton instance
_registry_instance: ModelRegistry | None = None
_instance_lock = threading.Lock()


def get_model_registry() -> ModelRegistry:
    """Obtain global singleton ModelRegistry instance."""
    global _registry_instance
    if _registry_instance is None:
        with _instance_lock:
            if _registry_instance is None:
                _registry_instance = ModelRegistry()
    return _registry_instance
