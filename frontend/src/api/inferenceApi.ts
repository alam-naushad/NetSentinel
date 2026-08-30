import { apiClient } from './client';
import {
  BatchFlowInferenceRequest,
  BatchFlowInferenceResponse,
  EvaluateFlowRequest,
  EvaluateFlowResponse,
  FlowInferenceRequest,
  FlowPredictionResponse,
} from '../types/inference';

export const inferenceApi = {
  predictSingle: (payload: FlowInferenceRequest) =>
    apiClient<FlowPredictionResponse>('/api/v1/predict/flow', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  predictBatch: (payload: BatchFlowInferenceRequest) =>
    apiClient<BatchFlowInferenceResponse>('/api/v1/predict/batch', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  evaluateDecision: (payload: EvaluateFlowRequest) =>
    apiClient<EvaluateFlowResponse>('/api/v1/decisions/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};
