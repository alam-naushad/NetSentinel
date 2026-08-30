import { FlowFeaturesInput } from '../types/flows';

export interface FeatureFieldMeta {
  key: keyof FlowFeaturesInput;
  label: string;
  description: string;
  unit?: string;
  category: 'network_ids' | 'traffic_rates' | 'packet_lengths' | 'tcp_flags' | 'iat_timings' | 'headers_windows' | 'active_idle';
}

export const FEATURE_CATEGORIES = [
  { id: 'network_ids', label: 'Network & Port Identifiers' },
  { id: 'traffic_rates', label: 'Traffic Rates & Packet Counts' },
  { id: 'packet_lengths', label: 'Packet Length Statistics' },
  { id: 'tcp_flags', label: 'TCP Control Flags' },
  { id: 'iat_timings', label: 'Inter-Arrival Time (IAT) Dynamics' },
  { id: 'headers_windows', label: 'TCP Windows & Header Sizes' },
  { id: 'active_idle', label: 'Flow Activity & Idle State' },
] as const;

export const FEATURE_FIELDS_METADATA: FeatureFieldMeta[] = [
  // Network & Port
  { key: 'destination_port', label: 'Destination Port', description: 'Destination service port number (0-65535)', category: 'network_ids' },
  
  // Rates & Counts
  { key: 'flow_bytes_per_sec', label: 'Flow Bytes / Sec', description: 'Flow transfer byte rate per second', unit: 'B/s', category: 'traffic_rates' },
  { key: 'fwd_packets_per_sec', label: 'Fwd Packets / Sec', description: 'Forward packets per second', unit: 'pkt/s', category: 'traffic_rates' },
  { key: 'bwd_packets_per_sec', label: 'Bwd Packets / Sec', description: 'Backward packets per second', unit: 'pkt/s', category: 'traffic_rates' },
  { key: 'total_forward_packets', label: 'Total Forward Packets', description: 'Total packet count in forward direction', category: 'traffic_rates' },
  { key: 'total_forward_bytes', label: 'Total Forward Bytes', description: 'Total bytes transferred forward', unit: 'bytes', category: 'traffic_rates' },
  { key: 'act_data_pkt_fwd', label: 'Forward Data Packets', description: 'Forward packets containing payload data', category: 'traffic_rates' },
  { key: 'down_up_ratio', label: 'Down / Up Ratio', description: 'Ratio of download to upload packets', category: 'traffic_rates' },

  // Lengths
  { key: 'packet_length_mean', label: 'Packet Length Mean', description: 'Mean packet length across flow', unit: 'bytes', category: 'packet_lengths' },
  { key: 'packet_length_variance', label: 'Packet Length Variance', description: 'Variance in packet length', category: 'packet_lengths' },
  { key: 'min_packet_length', label: 'Min Packet Length', description: 'Minimum packet length in flow', unit: 'bytes', category: 'packet_lengths' },
  { key: 'max_packet_length', label: 'Max Packet Length', description: 'Maximum packet length in flow', unit: 'bytes', category: 'packet_lengths' },
  { key: 'fwd_packet_length_max', label: 'Fwd Packet Length Max', description: 'Maximum forward packet length', unit: 'bytes', category: 'packet_lengths' },
  { key: 'fwd_packet_length_min', label: 'Fwd Packet Length Min', description: 'Minimum forward packet length', unit: 'bytes', category: 'packet_lengths' },
  { key: 'bwd_packet_length_mean', label: 'Bwd Packet Length Mean', description: 'Mean backward packet length', unit: 'bytes', category: 'packet_lengths' },
  { key: 'bwd_packet_length_std', label: 'Bwd Packet Length Std', description: 'Standard deviation of backward length', category: 'packet_lengths' },
  { key: 'bwd_packet_length_min', label: 'Bwd Packet Length Min', description: 'Minimum backward packet length', unit: 'bytes', category: 'packet_lengths' },
  { key: 'avg_fwd_segment_size', label: 'Avg Fwd Segment Size', description: 'Average forward segment size', unit: 'bytes', category: 'packet_lengths' },

  // TCP Flags
  { key: 'fin_flag_count', label: 'FIN Flag Count', description: 'Connection termination flags count', category: 'tcp_flags' },
  { key: 'syn_flag_count', label: 'SYN Flag Count', description: 'Connection synchronization flags count', category: 'tcp_flags' },
  { key: 'psh_flag_count', label: 'PSH Flag Count', description: 'Push data flags count', category: 'tcp_flags' },
  { key: 'ack_flag_count', label: 'ACK Flag Count', description: 'Acknowledgment flags count', category: 'tcp_flags' },
  { key: 'urg_flag_count', label: 'URG Flag Count', description: 'Urgent flags count', category: 'tcp_flags' },
  { key: 'ece_flag_count', label: 'ECE Flag Count', description: 'ECN-Echo congestion flags count', category: 'tcp_flags' },
  { key: 'fwd_urg_flags', label: 'Fwd URG Flags', description: 'Forward urgent flags count', category: 'tcp_flags' },

  // IAT Timings
  { key: 'flow_iat_mean', label: 'Flow IAT Mean', description: 'Mean inter-arrival time across flow', unit: 'µs', category: 'iat_timings' },
  { key: 'flow_iat_std', label: 'Flow IAT Std', description: 'Standard deviation of flow IAT', unit: 'µs', category: 'iat_timings' },
  { key: 'flow_iat_min', label: 'Flow IAT Min', description: 'Minimum inter-arrival time', unit: 'µs', category: 'iat_timings' },
  { key: 'fwd_iat_total', label: 'Fwd IAT Total', description: 'Total forward inter-arrival duration', unit: 'µs', category: 'iat_timings' },
  { key: 'fwd_iat_mean', label: 'Fwd IAT Mean', description: 'Mean forward inter-arrival time', unit: 'µs', category: 'iat_timings' },
  { key: 'fwd_iat_std', label: 'Fwd IAT Std', description: 'Standard deviation of forward IAT', unit: 'µs', category: 'iat_timings' },
  { key: 'fwd_iat_min', label: 'Fwd IAT Min', description: 'Minimum forward inter-arrival time', unit: 'µs', category: 'iat_timings' },
  { key: 'bwd_iat_total', label: 'Bwd IAT Total', description: 'Total backward inter-arrival duration', unit: 'µs', category: 'iat_timings' },
  { key: 'bwd_iat_mean', label: 'Bwd IAT Mean', description: 'Mean backward inter-arrival time', unit: 'µs', category: 'iat_timings' },
  { key: 'bwd_iat_std', label: 'Bwd IAT Std', description: 'Standard deviation of backward IAT', unit: 'µs', category: 'iat_timings' },
  { key: 'bwd_iat_max', label: 'Bwd IAT Max', description: 'Maximum backward inter-arrival time', unit: 'µs', category: 'iat_timings' },
  { key: 'bwd_iat_min', label: 'Bwd IAT Min', description: 'Minimum backward inter-arrival time', unit: 'µs', category: 'iat_timings' },

  // Windows & Headers
  { key: 'fwd_header_length', label: 'Fwd Header Length', description: 'Total forward header length in bytes', unit: 'bytes', category: 'headers_windows' },
  { key: 'bwd_header_length', label: 'Bwd Header Length', description: 'Total backward header length in bytes', unit: 'bytes', category: 'headers_windows' },
  { key: 'min_seg_size_fwd', label: 'Min Seg Size Fwd', description: 'Minimum TCP segment size in forward direction', unit: 'bytes', category: 'headers_windows' },
  { key: 'init_win_bytes_fwd', label: 'Init Win Bytes Fwd', description: 'Initial TCP window size in forward direction', unit: 'bytes', category: 'headers_windows' },
  { key: 'init_win_bytes_bwd', label: 'Init Win Bytes Bwd', description: 'Initial TCP window size in backward direction', unit: 'bytes', category: 'headers_windows' },

  // Active / Idle
  { key: 'active_mean', label: 'Active Mean', description: 'Mean time flow was active between idles', unit: 'µs', category: 'active_idle' },
  { key: 'active_std', label: 'Active Std', description: 'Standard deviation of active duration', unit: 'µs', category: 'active_idle' },
  { key: 'active_max', label: 'Active Max', description: 'Maximum active time', unit: 'µs', category: 'active_idle' },
  { key: 'active_min', label: 'Active Min', description: 'Minimum active time', unit: 'µs', category: 'active_idle' },
  { key: 'idle_min', label: 'Idle Min', description: 'Minimum idle duration before reactivation', unit: 'µs', category: 'active_idle' },
  { key: 'idle_std', label: 'Idle Std', description: 'Standard deviation of idle duration', unit: 'µs', category: 'active_idle' },
];
