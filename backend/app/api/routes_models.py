"""Model metadata and catalog API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from app.schemas.models import ModelCatalogResponse, ModelMetadataResponse
from app.services.model_registry import (
    DEFAULT_ANOMALY_MODEL_KEY,
    DEFAULT_SUPERVISED_MODEL_KEY,
    get_model_registry,
)

router = APIRouter(prefix="/models", tags=["models"])


@router.get("", response_model=ModelCatalogResponse)
def list_models() -> ModelCatalogResponse:
    """List all available ML model artifacts in the catalog with provenance metadata."""
    registry = get_model_registry()
    model_summaries = registry.list_models()

    models_response = [
        ModelMetadataResponse(
            model_key=s.model_key,
            model_name=s.model_name,
            protocol=s.protocol,
            feature_set=s.feature_set,
            n_features=s.n_features,
            model_role=s.model_role,
            deployment_tier=s.deployment_tier,
            class_names=s.class_names,
            thresholds=s.thresholds,
            training_rows=s.training_rows,
            training_time_seconds=s.training_time_seconds,
            artifact_size_bytes=s.artifact_size_bytes,
            artifact_sha256=s.artifact_sha256,
            scaling_applied=s.scaling_applied,
        )
        for s in model_summaries
    ]

    return ModelCatalogResponse(
        total_models=len(models_response),
        default_supervised_model=DEFAULT_SUPERVISED_MODEL_KEY,
        default_anomaly_model=DEFAULT_ANOMALY_MODEL_KEY,
        models=models_response,
    )


@router.get("/{model_key}", response_model=ModelMetadataResponse)
def get_model_metadata(model_key: str) -> ModelMetadataResponse:
    """Retrieve detailed metadata and checksum provenance for a specific model artifact."""
    registry = get_model_registry()
    try:
        bundle = registry.get_model(model_key)
        summary = bundle.to_summary()
        return ModelMetadataResponse(
            model_key=summary.model_key,
            model_name=summary.model_name,
            protocol=summary.protocol,
            feature_set=summary.feature_set,
            n_features=summary.n_features,
            model_role=summary.model_role,
            deployment_tier=summary.deployment_tier,
            class_names=summary.class_names,
            thresholds=summary.thresholds,
            training_rows=summary.training_rows,
            training_time_seconds=summary.training_time_seconds,
            artifact_size_bytes=summary.artifact_size_bytes,
            artifact_sha256=summary.artifact_sha256,
            scaling_applied=summary.scaling_applied,
        )
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to inspect model artifact '{model_key}': {e}",
        ) from e
