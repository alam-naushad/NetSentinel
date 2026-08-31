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

// ---------------------------------------------------------------
// Stage 9B — Real-Time Ingestion & SSE Types
// ---------------------------------------------------------------

export interface ZeekLiveEvent {
  sequence_id: number;
  session_id: string;
  ts: number;
  uid: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  service: string | null;
  duration_sec: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  conn_state: string | null;
  orig_pkts: number | null;
  resp_pkts: number | null;
  history: string | null;
  event_timestamp: string;
  persisted: boolean;
}

export interface ZeekIngestionCounters {
  records_read: number;
  records_parsed: number;
  records_malformed: number;
  records_duplicate: number;
  records_persisted: number;
  batches_persisted: number;
  batches_failed: number;
  persist_errors: number;
  queue_depth: number;
  queue_high_watermark: number;
  sse_clients_connected: number;
  sse_events_published: number;
  sse_events_dropped: number;
}

export interface ZeekIngestionBatchInfo {
  ingestion_lag_ms: number;
  flush_latency_ms: number;
  records_in_batch: number;
}

export interface ZeekTrackedFile {
  file_name: string;
  byte_offset: number;
  lines_processed: number;
  last_updated: string | null;
}

export interface ZeekIngestionStatus {
  enabled: boolean;
  status: 'running' | 'stopped' | 'paused' | 'disabled';
  spool_directory: string;
  uptime_seconds: number;
  counters: ZeekIngestionCounters;
  latest_batch: ZeekIngestionBatchInfo;
  tracked_files: ZeekTrackedFile[];
  sse_session_id: string | null;
}

export type ZeekSSEConnectionState = 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'DISCONNECTED' | 'DISABLED';

