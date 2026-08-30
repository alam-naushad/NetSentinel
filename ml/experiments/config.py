"""Configuration and schema definitions for Stage 3 baseline ML experiments."""

from pathlib import Path

RANDOM_SEED = 42

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data" / "extracted" / "MachineLearningCVE"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
DOCS_EXP_DIR = BASE_DIR / "docs" / "experiments"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
REPORTS_DIR = ARTIFACTS_DIR / "reports"
MODELS_DIR = ARTIFACTS_DIR / "models"

# 8 Official CSV files in CICIDS2017
RAW_CSV_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# Protocol B Split Mapping (Day / Capture-Aware)
PROTOCOL_B_TRAIN_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

PROTOCOL_B_TEST_FILES = [
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# Canonical Attack Family Mapping (Preserves DOS vs DDOS distinction)
# Web attacks with various dash encodings mapped consistently
RAW_LABEL_TO_FAMILY = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DOS",
    "DoS GoldenEye": "DOS",
    "DoS slowloris": "DOS",
    "DoS Slowhttptest": "DOS",
    "Heartbleed": "DOS",
    "DDoS": "DDOS",
    "PortScan": "PORT_SCAN",
    "FTP-Patator": "BRUTE_FORCE",
    "SSH-Patator": "BRUTE_FORCE",
    "Bot": "BOT",
    "Infiltration": "INFILTRATION",
    "Web Attack – Brute Force": "WEB_ATTACK",
    "Web Attack – XSS": "WEB_ATTACK",
    "Web Attack – Sql Injection": "WEB_ATTACK",
    "Web Attack - Brute Force": "WEB_ATTACK",
    "Web Attack - XSS": "WEB_ATTACK",
    "Web Attack - Sql Injection": "WEB_ATTACK",
}

# Statistically rare classes with very small support
RARE_CLASSES = ["Heartbleed", "Infiltration", "Web Attack – Sql Injection"]

# Complete 78 numeric flow feature headers in original CSV order
RAW_NUMERIC_FEATURE_HEADERS = [
    " Destination Port",
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Mean",
    " Fwd Packet Length Std",
    "Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Mean",
    " Bwd Packet Length Std",
    "Flow Bytes/s",
    " Flow Packets/s",
    " Flow IAT Mean",
    " Flow IAT Std",
    " Flow IAT Max",
    " Flow IAT Min",
    "Fwd IAT Total",
    " Fwd IAT Mean",
    " Fwd IAT Std",
    " Fwd IAT Max",
    " Fwd IAT Min",
    "Bwd IAT Total",
    " Bwd IAT Mean",
    " Bwd IAT Std",
    " Bwd IAT Max",
    " Bwd IAT Min",
    "Fwd PSH Flags",
    " Bwd PSH Flags",
    " Fwd URG Flags",
    " Bwd URG Flags",
    " Fwd Header Length",
    " Bwd Header Length",
    "Fwd Packets/s",
    " Bwd Packets/s",
    " Min Packet Length",
    " Max Packet Length",
    " Packet Length Mean",
    " Packet Length Std",
    " Packet Length Variance",
    "FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    " CWE Flag Count",
    " ECE Flag Count",
    " Down/Up Ratio",
    " Average Packet Size",
    " Avg Fwd Segment Size",
    " Avg Bwd Segment Size",
    " Fwd Header Length.1",  # duplicate column index 55 in raw CSVs
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",
    " act_data_pkt_fwd",
    " min_seg_size_forward",
    "Active Mean",
    " Active Std",
    " Active Max",
    " Active Min",
    "Idle Mean",
    " Idle Std",
    " Idle Max",
    " Idle Min",
]

# Standardized snake_case feature names (78 features + 1 duplicate column handled)
FEATURE_NAME_MAP = {
    " Destination Port": "destination_port",
    " Flow Duration": "flow_duration_ms",
    " Total Fwd Packets": "total_forward_packets",
    " Total Backward Packets": "total_backward_packets",
    "Total Length of Fwd Packets": "total_forward_bytes",
    " Total Length of Bwd Packets": "total_backward_bytes",
    " Fwd Packet Length Max": "fwd_packet_length_max",
    " Fwd Packet Length Min": "fwd_packet_length_min",
    " Fwd Packet Length Mean": "fwd_packet_length_mean",
    " Fwd Packet Length Std": "fwd_packet_length_std",
    "Bwd Packet Length Max": "bwd_packet_length_max",
    " Bwd Packet Length Min": "bwd_packet_length_min",
    " Bwd Packet Length Mean": "bwd_packet_length_mean",
    " Bwd Packet Length Std": "bwd_packet_length_std",
    "Flow Bytes/s": "flow_bytes_per_sec",
    " Flow Packets/s": "flow_packets_per_sec",
    " Flow IAT Mean": "flow_iat_mean",
    " Flow IAT Std": "flow_iat_std",
    " Flow IAT Max": "flow_iat_max",
    " Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_total",
    " Fwd IAT Mean": "fwd_iat_mean",
    " Fwd IAT Std": "fwd_iat_std",
    " Fwd IAT Max": "fwd_iat_max",
    " Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_total",
    " Bwd IAT Mean": "bwd_iat_mean",
    " Bwd IAT Std": "bwd_iat_std",
    " Bwd IAT Max": "bwd_iat_max",
    " Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    " Bwd PSH Flags": "bwd_psh_flags",
    " Fwd URG Flags": "fwd_urg_flags",
    " Bwd URG Flags": "bwd_urg_flags",
    " Fwd Header Length": "fwd_header_length",
    " Bwd Header Length": "bwd_header_length",
    "Fwd Packets/s": "fwd_packets_per_sec",
    " Bwd Packets/s": "bwd_packets_per_sec",
    " Min Packet Length": "min_packet_length",
    " Max Packet Length": "max_packet_length",
    " Packet Length Mean": "packet_length_mean",
    " Packet Length Std": "packet_length_std",
    " Packet Length Variance": "packet_length_variance",
    "FIN Flag Count": "fin_flag_count",
    " SYN Flag Count": "syn_flag_count",
    " RST Flag Count": "rst_flag_count",
    " PSH Flag Count": "psh_flag_count",
    " ACK Flag Count": "ack_flag_count",
    " URG Flag Count": "urg_flag_count",
    " CWE Flag Count": "cwe_flag_count",
    " ECE Flag Count": "ece_flag_count",
    " Down/Up Ratio": "down_up_ratio",
    " Average Packet Size": "average_packet_size",
    " Avg Fwd Segment Size": "avg_fwd_segment_size",
    " Avg Bwd Segment Size": "avg_bwd_segment_size",
    " Fwd Header Length.1": "fwd_header_length_dup",
    "Fwd Avg Bytes/Bulk": "fwd_avg_bytes_bulk",
    " Fwd Avg Packets/Bulk": "fwd_avg_packets_bulk",
    " Fwd Avg Bulk Rate": "fwd_avg_bulk_rate",
    " Bwd Avg Bytes/Bulk": "bwd_avg_bytes_bulk",
    " Bwd Avg Packets/Bulk": "bwd_avg_packets_bulk",
    "Bwd Avg Bulk Rate": "bwd_avg_bulk_rate",
    "Subflow Fwd Packets": "subflow_fwd_packets",
    " Subflow Fwd Bytes": "subflow_fwd_bytes",
    " Subflow Bwd Packets": "subflow_bwd_packets",
    " Subflow Bwd Bytes": "subflow_bwd_bytes",
    "Init_Win_bytes_forward": "init_win_bytes_fwd",
    " Init_Win_bytes_backward": "init_win_bytes_bwd",
    " act_data_pkt_fwd": "act_data_pkt_fwd",
    " min_seg_size_forward": "min_seg_size_fwd",
    "Active Mean": "active_mean",
    " Active Std": "active_std",
    " Active Max": "active_max",
    " Active Min": "active_min",
    "Idle Mean": "idle_mean",
    " Idle Std": "idle_std",
    " Idle Max": "idle_max",
    " Idle Min": "idle_min",
}

# Unique 78 numeric feature column names (excluding duplicate header column 55)
UNIQUE_FEATURE_NAMES = [
    v for k, v in FEATURE_NAME_MAP.items() if v != "fwd_header_length_dup"
]
