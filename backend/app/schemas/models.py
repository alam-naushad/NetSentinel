"""Pydantic schemas for Model Registry and metadata inspection."""

from __future__ import annotations

from pydantic import BaseModel, Field
from app.domain import DeploymentTier, ModelProtocol, ModelRole


class ModelMetadataResponse(BaseModel):
    """Detailed metadata and version provenance for a loaded model artifact."""

    model_key: str = Field(..., description="Unique catalog key for model selection")
    model_name: str = Field(..., description="Model architecture name (e.g. XGBoost, IsolationForest)")
    protocol: ModelProtocol = Field(..., description="Evaluation protocol: 'A' (Standard) or 'B' (Cross-Capture)")
    feature_set: str = Field(..., description="Feature set version: 'K48' (Primary) or 'K47' (Port-Ablated)")
    n_features: int = Field(..., description="Number of expected features")
    model_role: ModelRole = Field(..., description="SUPERVISED_CLASSIFIER or STATISTICAL_ANOMALY_DETECTOR")
    deployment_tier: DeploymentTier = Field(..., description="PRODUCTION_DEFAULT, PRODUCTION_ALTERNATIVE, or RESEARCH_EVALUATION")
    class_names: list[str] = Field(default_factory=list, description="Ordered class vocabulary")
    thresholds: dict[str, float] | None = Field(default=None, description="Calibrated decision thresholds if applicable")
    training_rows: int | None = Field(default=None, description="Number of training samples")
    training_time_seconds: float | None = Field(default=None, description="Training duration in seconds")
    artifact_size_bytes: int = Field(..., description="Size of serialized .joblib artifact on disk")
    artifact_sha256: str = Field(..., description="SHA-256 integrity checksum of artifact")
    scaling_applied: bool = Field(..., description="Whether StandardScaler transformation is active")


class ModelCatalogResponse(BaseModel):
    """Catalog inventory of available model artifacts in the platform."""

    total_models: int
    default_supervised_model: str
    default_anomaly_model: str
    models: list[ModelMetadataResponse]
