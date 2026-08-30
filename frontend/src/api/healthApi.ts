import { apiClient } from './client';

export interface HealthResponse {
  status: string;
  service: string;
}

export const healthApi = {
  getHealth: () => apiClient<HealthResponse>('/api/v1/health'),
};
