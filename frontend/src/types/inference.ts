import { DetectionStatus, Severity } from './domain';
import { ContextualSignals, FlowFeaturesInput } from './flows';

export interface FlowInferenceRequest {
  flow: FlowFeaturesInput;
  supervised_model_key?: string;
  anomaly_model_key?: string;
}

export interface FlowPredictionResponse {
  predicted_family: string;
  class_confidence: number;
  class_probabilities: Record<string, number>;
  raw_decision_score: number;
  is_statistical_anomaly: boolean;
  calibrated_threshold?: number | null;
  normalized_anomaly_score: number;
  inference_latency_ms: number;
  supervised_model_key: string;
  anomaly_model_key: string;
}

export interface BatchFlowInferenceRequest {
  flows: FlowFeaturesInput[];
  supervised_model_key?: string;
  anomaly_model_key?: string;
}

export interface BatchFlowInferenceResponse {
  total_flows: number;
  total_latency_ms: number;
  average_latency_ms: number;
  summary: Record<string, number>;
  predictions: FlowPredictionResponse[];
}

export interface DecisionPreviewResponse {
  status: DetectionStatus;
  severity: Severity;
  risk_score: number;
  explanation: string;
  policy_version: string;
}

export interface EvaluateFlowRequest {
  flow: FlowFeaturesInput;
  context?: ContextualSignals;
  supervised_model_key?: string;
  anomaly_model_key?: string;
}

export interface EvaluateFlowResponse {
  decision: DecisionPreviewResponse;
  prediction: FlowPredictionResponse;
  context_applied: ContextualSignals;
}

export interface SessionEvaluationRecord {
  id: string;
  timestamp: string;
  flow: FlowFeaturesInput;
  context: ContextualSignals;
  prediction: FlowPredictionResponse;
  decision: DecisionPreviewResponse;
}
