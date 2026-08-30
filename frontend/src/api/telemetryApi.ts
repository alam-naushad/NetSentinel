import { apiClient } from './client';
import {
  AnalysisJobSummary,
  PageResponse,
  SecurityEventDetail,
  SecurityEventSummary,
  TelemetrySummaryStats,
} from '../types/telemetry';

export interface EventSearchParams {
  page?: number;
  page_size?: number;
  start_time?: string;
  end_time?: string;
  severity?: string[];
  triage_status?: string[];
  attack_family?: string[];
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  min_risk_score?: number;
  max_risk_score?: number;
  is_statistical_anomaly?: boolean;
  job_id?: string;
  sort_by?: string;
  sort_order?: string;
}

export const telemetryApi = {
  getEvents: (params: EventSearchParams = {}) => {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.page_size) query.append('page_size', params.page_size.toString());
    if (params.start_time) query.append('start_time', params.start_time);
    if (params.end_time) query.append('end_time', params.end_time);
    if (params.src_ip) query.append('src_ip', params.src_ip);
    if (params.dst_ip) query.append('dst_ip', params.dst_ip);
    if (params.protocol) query.append('protocol', params.protocol);
    if (params.min_risk_score !== undefined) query.append('min_risk_score', params.min_risk_score.toString());
    if (params.max_risk_score !== undefined) query.append('max_risk_score', params.max_risk_score.toString());
    if (params.is_statistical_anomaly !== undefined) query.append('is_statistical_anomaly', params.is_statistical_anomaly.toString());
    if (params.job_id) query.append('job_id', params.job_id);
    if (params.sort_by) query.append('sort_by', params.sort_by);
    if (params.sort_order) query.append('sort_order', params.sort_order);

    if (params.severity) {
      params.severity.forEach((s) => query.append('severity', s));
    }
    if (params.triage_status) {
      params.triage_status.forEach((t) => query.append('triage_status', t));
    }
    if (params.attack_family) {
      params.attack_family.forEach((a) => query.append('attack_family', a));
    }

    return apiClient<PageResponse<SecurityEventSummary>>(`/api/v1/telemetry/events?${query.toString()}`);
  },

  getEventDetail: (eventId: string) =>
    apiClient<SecurityEventDetail>(`/api/v1/telemetry/events/${encodeURIComponent(eventId)}`),

  getJobs: (page = 1, pageSize = 20) =>
    apiClient<PageResponse<AnalysisJobSummary>>(`/api/v1/telemetry/jobs?page=${page}&page_size=${pageSize}`),

  getJobDetail: (jobId: string) =>
    apiClient<AnalysisJobSummary>(`/api/v1/telemetry/jobs/${encodeURIComponent(jobId)}`),

  getSummaryStats: (timeWindow = '24h') =>
    apiClient<TelemetrySummaryStats>(`/api/v1/telemetry/stats/summary?time_window=${timeWindow}`),
};
