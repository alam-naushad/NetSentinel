export interface ZeekConnectionSummary {
  zeek_uid: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: string;
  service: string | null;
  duration_sec: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  conn_state: string | null;
  history: string | null;
  orig_pkts: number | null;
  resp_pkts: number | null;
  missed_bytes: number | null;
}

export interface ZeekAnalysisSummary {
  filename: string;
  file_size_bytes: number;
  total_connections_parsed: number;
  total_connections_persisted: number;
  connections_skipped_malformed: number;
  connections_skipped_duplicate: number;
  protocol_distribution: Record<string, number>;
  service_distribution: Record<string, number>;
  conn_state_distribution: Record<string, number>;
  processing_time_ms: number;
  ml_classification_performed: false;
  analysis_type: 'TELEMETRY_ONLY';
}

export interface ZeekAnalysisResponse {
  summary: ZeekAnalysisSummary;
  connections: ZeekConnectionSummary[];
  job_id: string | null;
  persisted: boolean;
  persistence_error: string | null;
}
