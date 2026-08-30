import { PcapFlowProvenance } from './pcap';

export interface PageResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface SecurityEventSummary {
  id: string;
  event_timestamp: string;
  source_channel: string;
  predicted_family: string;
  class_confidence: number;
  normalized_anomaly_score: number;
  is_statistical_anomaly: boolean;
  risk_score: number;
  severity: string;
  triage_status: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol_name: string;
  job_id?: string | null;
  has_alert: boolean;
}

export interface SecurityEventDetail {
  id: string;
  event_timestamp: string;
  source_channel: string;
  predicted_family: string;
  class_confidence: number;
  class_probabilities: Record<string, number>;
  normalized_anomaly_score: number;
  raw_decision_score: number;
  is_statistical_anomaly: boolean;
  risk_score: number;
  severity: string;
  triage_status: string;
  explanation: string;
  supervised_model_key: string;
  anomaly_model_key: string;
  provenance: PcapFlowProvenance;
  feature_vector: Record<string, number>;
  alert_id?: string | null;
  job_id?: string | null;
}

export interface AnalysisJobSummary {
  id: string;
  source_type: string;
  filename: string;
  file_size_bytes: number;
  file_sha256?: string | null;
  total_flows_extracted: number;
  total_flows_analyzed: number;
  anomalies_flagged: number;
  processing_time_ms: number;
  status: string;
  created_at: string;
}

export interface TelemetrySummaryStats {
  total_events: number;
  total_attacks: number;
  total_benign: number;
  total_anomalies: number;
  attack_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  time_window: string;
}
