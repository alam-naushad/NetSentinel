import { DeploymentTier, ModelProtocol, ModelRole } from './domain';

export interface ModelMetadata {
  model_key: string;
  model_name: string;
  protocol: ModelProtocol;
  feature_set: string;
  n_features: number;
  model_role: ModelRole;
  deployment_tier: DeploymentTier;
  class_names: string[];
  thresholds?: Record<string, number> | null;
  training_rows?: number | null;
  training_time_seconds?: number | null;
  artifact_size_bytes: number;
  artifact_sha256: string;
  scaling_applied: boolean;
}

export interface ModelCatalogResponse {
  total_models: number;
  default_supervised_model: string;
  default_anomaly_model: string;
  models: ModelMetadata[];
}
