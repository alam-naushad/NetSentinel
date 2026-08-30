export interface ApiError {
  status: number;
  message: string;
  error?: string;
  missing_features?: string[];
  invalid_fields?: string[];
}

export async function apiClient<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    const isJson = response.headers.get('content-type')?.includes('application/json');
    const data = isJson ? await response.json() : null;

    if (!response.ok) {
      let errorMessage = `Request failed with status ${response.status}`;
      let missing_features: string[] | undefined;
      let invalid_fields: string[] | undefined;

      if (data && typeof data === 'object') {
        if (data.detail) {
          if (typeof data.detail === 'string') {
            errorMessage = data.detail;
          } else if (typeof data.detail === 'object') {
            errorMessage = data.detail.message || JSON.stringify(data.detail);
            missing_features = data.detail.missing_features;
            invalid_fields = data.detail.invalid_fields;
          }
        } else if (data.message) {
          errorMessage = data.message;
          missing_features = data.missing_features;
          invalid_fields = data.invalid_fields;
        }
      }

      const apiErr: ApiError = {
        status: response.status,
        message: errorMessage,
        error: data?.error,
        missing_features,
        invalid_fields,
      };
      throw apiErr;
    }

    return data as T;
  } catch (err: any) {
    if (err.status) {
      throw err;
    }
    throw {
      status: 0,
      message: err.message || 'Network connection to backend service failed. Please ensure FastAPI is running.',
    } as ApiError;
  }
}
