export interface FlowFeaturesInput {
  destination_port: number;
  flow_bytes_per_sec: number;
  fwd_packets_per_sec: number;
  bwd_packets_per_sec: number;
  min_packet_length: number;
  max_packet_length: number;
  packet_length_mean: number;
  packet_length_variance: number;
  fin_flag_count: number;
  syn_flag_count: number;
  psh_flag_count: number;
  ack_flag_count: number;
  urg_flag_count: number;
  ece_flag_count: number;
  down_up_ratio: number;
  avg_fwd_segment_size: number;
  fwd_header_length: number;
  bwd_header_length: number;
  min_seg_size_fwd: number;
  act_data_pkt_fwd: number;
  init_win_bytes_fwd: number;
  init_win_bytes_bwd: number;
  active_mean: number;
  active_std: number;
  active_max: number;
  active_min: number;
  idle_std: number;
  idle_min: number;
  fwd_iat_total: number;
  fwd_iat_mean: number;
  fwd_iat_std: number;
  fwd_iat_min: number;
  bwd_iat_total: number;
  bwd_iat_mean: number;
  bwd_iat_std: number;
  bwd_iat_max: number;
  bwd_iat_min: number;
  flow_iat_mean: number;
  flow_iat_std: number;
  flow_iat_min: number;
  fwd_packet_length_max: number;
  fwd_packet_length_min: number;
  bwd_packet_length_min: number;
  bwd_packet_length_mean: number;
  bwd_packet_length_std: number;
  total_forward_packets: number;
  total_forward_bytes: number;
  fwd_urg_flags: number;
}

export interface ContextualSignals {
  repeated_source_events?: number;
  targets_sensitive_service?: boolean;
}
