import { ZeekAnalysisResponse } from '../types/zeek';
import { ApiError } from './client';

export const zeekApi = {
  analyzeZeekLog: async (file: File): Promise<ZeekAnalysisResponse> => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/v1/zeek/analyze', {
        method: 'POST',
        body: formData,
      });

      const isJson = response.headers.get('content-type')?.includes('application/json');
      const data = isJson ? await response.json() : null;

      if (!response.ok) {
        let errorMessage = `Upload failed with status ${response.status}`;
        if (data && typeof data === 'object') {
          if (typeof data.detail === 'string') {
            errorMessage = data.detail;
          } else if (typeof data.detail === 'object' && data.detail.message) {
            errorMessage = data.detail.message;
          } else if (data.message) {
            errorMessage = data.message;
          }
        }
        const apiErr: ApiError = {
          status: response.status,
          message: errorMessage,
          error: data?.error,
        };
        throw apiErr;
      }

      return data as ZeekAnalysisResponse;
    } catch (err: any) {
      if (err.status !== undefined) {
        throw err;
      }
      throw {
        status: 0,
        message: err.message || 'Failed to upload Zeek file to backend service.',
      } as ApiError;
    }
  },
};
