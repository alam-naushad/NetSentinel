export type DriftSeverity = 'STABLE' | 'MODERATE' | 'SIGNIFICANT';
export type OverallDriftStatus = 'STABLE' | 'MODERATE_DRIFT' | 'SIGNIFICANT_DRIFT' | 'INSUFFICIENT_DATA';

export interface DriftDataQuality {
  finite_count: number;
  zero_count: number;
  zero_fraction: number;
  is_constant_baseline: boolean;
  is_constant_observed: boolean;
  bin_type: string;
}

export interface FeatureDriftResult {
  feature_name: string;
  canonical_index: number;
  sample_count: number;
  baseline_mean: number;
  observed_mean: number;
  baseline_std: number;
  observed_std: number;
  psi: number;
  smd: number | null;
  drift_severity: DriftSeverity;
  data_quality: DriftDataQuality;
}

export interface DatasetDriftSummary {
  evaluated_flow_count: number;
  evaluated_feature_count: number;
  stable_feature_count: number;
  moderate_feature_count: number;
  significant_feature_count: number;
  overall_drift_status: OverallDriftStatus;
  mean_psi: number;
  max_psi: number;
  top_drifting_features: string[];
  is_sample_size_sufficient: boolean;
  insufficient_sample_reason: string | null;
  evaluation_time_ms: number;
  baseline_dataset: string;
  baseline_sample_count: number;
  disclaimer: string;
}

export interface DriftEvaluationResponse {
  summary: DatasetDriftSummary;
  feature_metrics: Record<string, FeatureDriftResult>;
}
