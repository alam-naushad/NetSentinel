"""Pydantic schemas for network flow telemetry and contextual signals."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FlowFeaturesInput(BaseModel):
    """Canonical 48-feature network flow schema matching Stage 3 feature selection contract."""

    model_config = ConfigDict(extra="forbid")

    # 1-10
    psh_flag_count: float = Field(..., ge=0, description="PSH flag count")
    bwd_packet_length_mean: float = Field(..., ge=0, description="Mean length of backward packets")
    min_seg_size_fwd: float = Field(..., ge=0, description="Minimum segment size in forward direction")
    bwd_packet_length_std: float = Field(..., ge=0, description="Standard deviation of backward packet length")
    bwd_packet_length_min: float = Field(..., ge=0, description="Minimum length of backward packets")
    max_packet_length: float = Field(..., ge=0, description="Maximum packet length across flow")
    destination_port: float = Field(..., ge=0, le=65535, description="Destination service port")
    ack_flag_count: float = Field(..., ge=0, description="ACK flag count")
    packet_length_mean: float = Field(..., ge=0, description="Mean packet length")
    fwd_iat_std: float = Field(..., ge=0, description="Standard deviation of forward inter-arrival time")

    # 11-20
    idle_min: float = Field(..., ge=0, description="Minimum idle time before flow activity")
    init_win_bytes_fwd: float = Field(..., description="Initial TCP window bytes in forward direction")
    packet_length_variance: float = Field(..., ge=0, description="Variance of packet length")
    min_packet_length: float = Field(..., ge=0, description="Minimum packet length")
    fwd_packet_length_max: float = Field(..., ge=0, description="Maximum length of forward packets")
    act_data_pkt_fwd: float = Field(..., ge=0, description="Count of forward data packets with payload")
    flow_iat_std: float = Field(..., ge=0, description="Standard deviation of flow inter-arrival time")
    total_forward_packets: float = Field(..., ge=0, description="Total forward packets in flow")
    down_up_ratio: float = Field(..., ge=0, description="Download/Upload ratio")
    flow_iat_mean: float = Field(..., ge=0, description="Mean flow inter-arrival time")

    # 21-30
    avg_fwd_segment_size: float = Field(..., ge=0, description="Average forward segment size")
    fwd_header_length: float = Field(..., description="Total forward header length in bytes")
    bwd_header_length: float = Field(..., description="Total backward header length in bytes")
    fwd_iat_total: float = Field(..., ge=0, description="Total forward inter-arrival time")
    fin_flag_count: float = Field(..., ge=0, description="FIN flag count")
    bwd_iat_total: float = Field(..., ge=0, description="Total backward inter-arrival time")
    fwd_packets_per_sec: float = Field(..., ge=0, description="Forward packets per second")
    urg_flag_count: float = Field(..., ge=0, description="URG flag count")
    init_win_bytes_bwd: float = Field(..., description="Initial TCP window bytes in backward direction")
    fwd_iat_mean: float = Field(..., ge=0, description="Mean forward inter-arrival time")

    # 31-40
    fwd_packet_length_min: float = Field(..., ge=0, description="Minimum length of forward packets")
    total_forward_bytes: float = Field(..., ge=0, description="Total bytes in forward direction")
    bwd_packets_per_sec: float = Field(..., ge=0, description="Backward packets per second")
    syn_flag_count: float = Field(..., ge=0, description="SYN flag count")
    bwd_iat_max: float = Field(..., ge=0, description="Maximum backward inter-arrival time")
    bwd_iat_mean: float = Field(..., ge=0, description="Mean backward inter-arrival time")
    bwd_iat_std: float = Field(..., ge=0, description="Standard deviation of backward inter-arrival time")
    active_mean: float = Field(..., ge=0, description="Mean time flow was active")
    flow_bytes_per_sec: float = Field(..., ge=0, description="Flow byte transfer rate per second")
    active_min: float = Field(..., ge=0, description="Minimum time flow was active")

    # 41-48
    flow_iat_min: float = Field(..., ge=0, description="Minimum flow inter-arrival time")
    active_max: float = Field(..., ge=0, description="Maximum time flow was active")
    fwd_iat_min: float = Field(..., ge=0, description="Minimum forward inter-arrival time")
    idle_std: float = Field(..., ge=0, description="Standard deviation of idle time")
    bwd_iat_min: float = Field(..., ge=0, description="Minimum backward inter-arrival time")
    active_std: float = Field(..., ge=0, description="Standard deviation of active time")
    fwd_urg_flags: float = Field(..., ge=0, description="Forward URG flags")
    ece_flag_count: float = Field(..., ge=0, description="ECE flag count")

    def to_dict(self) -> dict[str, float]:
        """Convert validated schema into dictionary."""
        return self.model_dump()


class ContextualSignals(BaseModel):
    """Safe contextual risk modifiers supplied by environment/telemetry metadata."""

    repeated_source_events: int = Field(default=0, ge=0, le=1000, description="Repeated historical incidents from source IP")
    targets_sensitive_service: bool = Field(default=False, description="Whether target destination host is a critical asset")
