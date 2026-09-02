import { apiClient } from './client';
import { User } from '../types/auth';

export const authApi = {
  getMe: (): Promise<User> => apiClient<User>('/api/v1/auth/me'),

  login: (credentials: { username: string; password: string }): Promise<User> =>
    apiClient<User>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    }),

  logout: (): Promise<{ status: string; message: string }> =>
    apiClient<{ status: string; message: string }>('/api/v1/auth/logout', {
      method: 'POST',
    }),
};
