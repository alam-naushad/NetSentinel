export interface AlertHistoryItem {
  id: string;
  timestamp: string;
  previous_disposition?: string | null;
  new_disposition: string;
  actor_id: string;
  action_note?: string | null;
}

export interface AlertSummary {
  id: string;
  event_id: string;
  alert_type: string;
  severity: string;
  disposition: string;
  analyst_notes?: string | null;
  policy_version_applied: string;
  created_at: string;
  resolved_at?: string | null;

  // Context from event
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol_name: string;
  predicted_family: string;
  class_confidence: number;
  risk_score: number;
  triage_status: string;
}

export interface AlertDetail extends AlertSummary {
  history: AlertHistoryItem[];
}

export interface UpdateAlertRequest {
  new_disposition: string;
  actor_id?: string;
  note?: string;
}
