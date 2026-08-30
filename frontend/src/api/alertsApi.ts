import { apiClient } from './client';
import { AlertDetail, AlertSummary, UpdateAlertRequest } from '../types/alerts';
import { PageResponse } from '../types/telemetry';

export interface AlertSearchParams {
  page?: number;
  page_size?: number;
  disposition?: string[];
  severity?: string[];
  alert_type?: string[];
  start_time?: string;
  end_time?: string;
  sort_by?: string;
  sort_order?: string;
}

export const alertsApi = {
  getAlerts: (params: AlertSearchParams = {}) => {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.page_size) query.append('page_size', params.page_size.toString());
    if (params.start_time) query.append('start_time', params.start_time);
    if (params.end_time) query.append('end_time', params.end_time);
    if (params.sort_by) query.append('sort_by', params.sort_by);
    if (params.sort_order) query.append('sort_order', params.sort_order);

    if (params.disposition) {
      params.disposition.forEach((d) => query.append('disposition', d));
    }
    if (params.severity) {
      params.severity.forEach((s) => query.append('severity', s));
    }
    if (params.alert_type) {
      params.alert_type.forEach((a) => query.append('alert_type', a));
    }

    return apiClient<PageResponse<AlertSummary>>(`/api/v1/alerts?${query.toString()}`);
  },

  getAlertDetail: (alertId: string) =>
    apiClient<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(alertId)}`),

  updateDisposition: (alertId: string, payload: UpdateAlertRequest) =>
    apiClient<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(alertId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
};
