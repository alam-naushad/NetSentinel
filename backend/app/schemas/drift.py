"""Pydantic schemas for Feature Drift Monitoring API."""

from __future__ import annotations

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.flows import FlowFeaturesInput

# Drift severity levels following standard statistical process monitoring heuristics
DriftSeverity = Literal["STABLE", "MODERATE", "SIGNIFICANT"]
OverallDriftStatus = Literal["STABLE", "MODERATE_DRIFT", "SIGNIFICANT_DRIFT", "INSUFFICIENT_DATA"]


class DriftDataQuality(BaseModel):
    """Quality and distribution indicators for a single evaluated feature."""
    model_config = ConfigDict(extra="ignore")

    finite_count: int = Field(..., description="Number of finite valid numeric values evaluated")
    zero_count: int = Field(..., description="Number of exact zero values observed")
    zero_fraction: float = Field(..., description="Proportion of observed values equal to zero")
    is_constant_baseline: bool = Field(False, description="Whether the baseline has zero variance")
    is_constant_observed: bool = Field(False, description="Whether the incoming sample has zero variance")
    bin_type: str = Field(..., description="Type of adaptive binning used: discrete, zero_inflated, continuous")


class FeatureDriftResult(BaseModel):
    """Statistical drift metrics for an individual canonical feature."""
    model_config = ConfigDict(extra="ignore")

    feature_name: str
    canonical_index: int
    sample_count: int
    baseline_mean: float
    observed_mean: float
    baseline_std: float
    observed_std: float
    psi: float = Field(..., description="Population Stability Index")
    smd: Optional[float] = Field(None, description="Standardized Mean Difference (Cohen's d); None if baseline std is zero")
    drift_severity: DriftSeverity
    data_quality: DriftDataQuality


class DatasetDriftSummary(BaseModel):
    """Aggregated dataset-level drift assessment across all canonical features."""
    model_config = ConfigDict(extra="ignore")

    evaluated_flow_count: int
    evaluated_feature_count: int
    stable_feature_count: int
    moderate_feature_count: int
    significant_feature_count: int
    overall_drift_status: OverallDriftStatus
    mean_psi: float
    max_psi: float
    top_drifting_features: List[str] = Field(default_factory=list, description="Top features ranked by PSI descending")
    is_sample_size_sufficient: bool = Field(..., description="True if sample_count >= minimum threshold (100)")
    insufficient_sample_reason: Optional[str] = None
    evaluation_time_ms: float
    baseline_dataset: str
    baseline_sample_count: int
    disclaimer: str = (
        "Feature drift measures statistical divergence from the benchmark training distribution (CICIDS2017) "
        "using operational PSI heuristics. When overall status is stable: no substantial distribution shift was detected "
        "under the configured PSI threshold; model performance was not assessed by this metric. A low PSI does not prove "
        "that model accuracy or confidence is maintained, and high PSI does not prove an attack is occurring. Drift monitoring "
        "does not measure prediction performance without suitable ground-truth labels."
    )


class DriftEvaluationResponse(BaseModel):
    """Complete response payload for a drift evaluation request."""
    model_config = ConfigDict(extra="ignore")

    summary: DatasetDriftSummary
    feature_metrics: Dict[str, FeatureDriftResult]


class BatchDriftEvaluationRequest(BaseModel):
    """Payload for on-demand batch feature drift evaluation."""
    model_config = ConfigDict(extra="ignore")

    flows: List[FlowFeaturesInput] = Field(
        ...,
        description="Batch of flow feature vectors conforming to canonical K=48 schema. Minimum 100 flows recommended.",
    )
