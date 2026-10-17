import { apiClient } from './client';
import { DriftEvaluationResponse } from '../types/drift';

export async function fetchTelemetryDrift(
  limit: number = 500,
  sourceChannel: string = 'PCAP_BATCH'
): Promise<DriftEvaluationResponse> {
  return apiClient<DriftEvaluationResponse>(
    `/api/v1/drift/telemetry-window?limit=${encodeURIComponent(limit)}&source_channel=${encodeURIComponent(sourceChannel)}`
  );
}

export async function evaluateBatchDrift(flows: any[]): Promise<DriftEvaluationResponse> {
  return apiClient<DriftEvaluationResponse>('/api/v1/drift/evaluate-batch', {
    method: 'POST',
    body: JSON.stringify({ flows }),
  });
}
