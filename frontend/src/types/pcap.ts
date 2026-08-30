import { DetectionStatus, Severity } from './domain';

export interface PcapFlowProvenance {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  ip_proto: number;
  protocol_name: string;
  start_time_iso: string;
  end_time_iso: string;
  duration_ms: number;
  total_packets: number;
  total_bytes: number;
}

export interface PcapFlowResult {
  provenance: PcapFlowProvenance;
  predicted_family: string;
  class_confidence: number;
  class_probabilities: Record<string, number>;
  raw_decision_score: number;
  is_statistical_anomaly: boolean;
  normalized_anomaly_score: number;
  risk_score: number;
  severity: Severity;
  status: DetectionStatus;
  explanation: string;
  features?: Record<string, number>;
}

export interface PcapAnalysisSummary {
  file_name: string;
  file_size_bytes: number;
  extracted_flows: number;
  analyzed_flows: number;
  skipped_flows: number;
  attack_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  anomalies_flagged: number;
  processing_time_ms: number;
  supervised_model_key: string;
  anomaly_model_key: string;
}

export interface PcapAnalysisResponse {
  summary: PcapAnalysisSummary;
  flows: PcapFlowResult[];
}
