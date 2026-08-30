import { apiClient } from './client';
import { ModelCatalogResponse, ModelMetadata } from '../types/models';

export const modelsApi = {
  getCatalog: () => apiClient<ModelCatalogResponse>('/api/v1/models'),
  getModel: (modelKey: string) => apiClient<ModelMetadata>(`/api/v1/models/${encodeURIComponent(modelKey)}`),
};
