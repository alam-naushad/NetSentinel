# 48-Feature Support & Parity Matrix: PCAP Ingestion & Flow Reconstruction

## 1. Overview & Scope

This document defines the mathematical extraction specification, state requirements, confidence levels, validation methodologies, and known semantic discrepancies for all **48 canonical model features** extracted from raw packet capture (`.pcap` / `.pcapng`) files.

### Legend & Confidence Classifications:
- **High Confidence**: Direct deterministic mapping from packet headers (e.g. port, packet counts, flags, initial window).
- **Medium Confidence**: Stateful temporal or statistical accumulators (e.g. inter-arrival time standard deviations, header sum conventions).
- **Conditional Confidence**: State-machine-dependent metrics (e.g. active/idle bursts requiring >= 5.0s activity gaps).

---

## 2. Exhaustive 48-Feature Extraction Specification

| # | Feature Name | Extraction Formula & State Representation | Required Flow State | Confidence Level | Validation Method | Known Semantic Nuances & Edge Cases |
| :---: | :--- | :--- | :--- | :---: | :--- | :--- |
| **1** | `destination_port` | `dst_port` of the initial forward packet. | 1st Packet (Forward) | **High** | Exact header comparison | Destination port in forward direction (0–65535). |
| **2** | `total_forward_packets` | Count of packets matching `(src_ip, src_port) == forward_endpoint`. | Forward Counter | **High** | Packet count sum | Monotonically increments on every forward packet. |
| **3** | `total_forward_bytes` | Sum of forward packet payload lengths (`len(tcp.data)` or `len(udp.data)`). | Forward Sum | **High** | Payload accumulator | Cumulative transport payload bytes. |
| **4** | `min_packet_length` | min(transport payload lengths across all flow packets). | Stateful Min | **High** | Packet inspection | Minimum transport payload length (0 for pure ACK/SYN). |
| **5** | `max_packet_length` | max(transport payload lengths across all flow packets). | Stateful Max | **High** | Packet inspection | Maximum transport payload length. |
| **6** | `packet_length_mean` | (1/N) * sum(L_i) where L_i = len(payload_i). | Mean Accumulator | **High** | Statistical mean | Arithmetic mean of transport payload lengths. |
| **7** | `packet_length_variance` | (1/(N-1)) * sum((L_i - mean_L)^2) with ddof=1. | Variance Accumulator | **High** | Sample variance | Evaluates strictly to 0.0 for single-packet flows (N=1). |
| **8** | `fwd_packet_length_max` | max(forward transport payload lengths). | Forward Max | **High** | Forward length check | Maximum payload length in forward direction. |
| **9** | `fwd_packet_length_min` | min(forward transport payload lengths). | Forward Min | **High** | Forward length check | Minimum payload length in forward direction. |
| **10**| `avg_fwd_segment_size` | sum(L_fwd_payload) / N_fwd. | Forward Mean | **High** | Forward length mean | In CICFlowMeter, equals mean forward payload size. |
| **11**| `bwd_packet_length_min` | min(backward transport payload lengths) (0.0 if N_bwd=0). | Backward Min | **High** | Backward length check| Evaluates to 0.0 if no backward packets observed. |
| **12**| `bwd_packet_length_mean`| (1/N_bwd) * sum(L_bwd_payload) (0.0 if N_bwd=0). | Backward Mean | **High** | Backward length mean | Evaluates to 0.0 if no backward packets observed. |
| **13**| `bwd_packet_length_std` | sqrt((1/(N_bwd-1)) * sum((L_j - mean_L_bwd)^2)) (0.0 if N_bwd <= 1). | Backward Std | **High** | Sample standard deviation | Evaluates to 0.0 if N_bwd <= 1. |
| **14**| `fin_flag_count` | sum(1 if TCP_FIN in pkt.flags else 0). | Flag Counter | **High** | Header flag bitwise check | Always 0 for UDP flows. |
| **15**| `syn_flag_count` | sum(1 if TCP_SYN in pkt.flags else 0). | Flag Counter | **High** | Header flag bitwise check | Always 0 for UDP flows. |
| **16**| `psh_flag_count` | sum(1 if TCP_PUSH in pkt.flags else 0). | Flag Counter | **High** | Header flag bitwise check | Always 0 for UDP flows. |
| **17**| `ack_flag_count` | sum(1 if TCP_ACK in pkt.flags else 0). | Flag Counter | **High** | Header flag bitwise check | Always 0 for UDP flows. |
| **18**| `urg_flag_count` | sum(1 if TCP_URG in pkt.flags else 0). | Flag Counter | **High** | Header flag bitwise check | Always 0 for UDP flows. |
| **19**| `ece_flag_count` | sum(1 if TCP_ECE in pkt.flags else 0). | Flag Counter | **High** | Header flag bitwise check | Always 0 for UDP flows. |
| **20**| `fwd_urg_flags` | sum_fwd(1 if TCP_URG in pkt.flags else 0). | Forward Flag Counter | **High** | Forward flag check | URG flags in forward direction only. |
| **21**| `fwd_header_length` | sum_fwd(IP_hdr_len + TCP_hdr_len). | Forward Header Sum | **Medium** | Header size accumulator | Sum of IP + transport header bytes. |
| **22**| `bwd_header_length` | sum_bwd(IP_hdr_len + TCP_hdr_len). | Backward Header Sum | **Medium** | Header size accumulator | 0 if no backward packets. |
| **23**| `min_seg_size_fwd` | min_fwd(TCP_hdr_len) (or 8 for UDP). | Forward Min Header | **Medium** | Minimum header check | Typically 20 or 32 bytes for TCP; 8 for UDP. |
| **24**| `init_win_bytes_fwd` | Initial TCP window bytes in first forward TCP packet. | 1st Forward TCP Header| **High** | TCP window inspection | Strictly -1.0 if non-TCP or unidirectional non-TCP. |
| **25**| `init_win_bytes_bwd` | Initial TCP window bytes in first backward TCP packet. | 1st Backward TCP Header| **High** | TCP window inspection | Strictly -1.0 if no backward TCP packet. |
| **26**| `act_data_pkt_fwd` | Count of forward packets with payload length > 0. | Forward Data Counter | **High** | Payload length check | Count of forward packets carrying data. |
| **27**| `down_up_ratio` | N_bwd / N_fwd (0.0 if N_fwd = 0). | Packet Ratio | **High** | Ratio calculation | Ratio of download to upload packet volume. |
| **28**| `fwd_iat_total` | t_fwd_last - t_fwd_first (us). | Forward Timestamps | **High** | Timestamp delta | Total forward duration in microseconds. |
| **29**| `fwd_iat_mean` | (1/(N_fwd-1)) * sum(delta_t_fwd) (us). | Forward IAT Queue | **High** | Mean calculation | Mean forward inter-arrival time (us). |
| **30**| `fwd_iat_std` | Sample standard deviation of forward IATs (us). | Forward IAT Queue | **Medium** | Sample standard deviation | 0.0 if N_fwd_iats <= 1. |
| **31**| `fwd_iat_min` | Minimum forward IAT (us) (0.0 if N_fwd <= 1). | Forward IAT Queue | **High** | Min delta | Minimum forward inter-arrival time (us). |
| **32**| `bwd_iat_total` | t_bwd_last - t_bwd_first (us). | Backward Timestamps | **High** | Timestamp delta | Total backward duration in microseconds. |
| **33**| `bwd_iat_mean` | (1/(N_bwd-1)) * sum(delta_t_bwd) (us). | Backward IAT Queue | **High** | Mean calculation | Mean backward inter-arrival time (us). |
| **34**| `bwd_iat_std` | Sample standard deviation of backward IATs (us). | Backward IAT Queue | **Medium** | Sample standard deviation | 0.0 if N_bwd_iats <= 1. |
| **35**| `bwd_iat_max` | Maximum backward IAT (us) (0.0 if N_bwd <= 1). | Backward IAT Queue | **High** | Max delta | Maximum backward inter-arrival time (us). |
| **36**| `bwd_iat_min` | Minimum backward IAT (us) (0.0 if N_bwd <= 1). | Backward IAT Queue | **High** | Min delta | Minimum backward inter-arrival time (us). |
| **37**| `flow_iat_mean` | (1/(N-1)) * sum(delta_t_flow) (us). | Flow-wide IAT Queue | **High** | Mean calculation | Mean inter-arrival time across all flow packets (us). |
| **38**| `flow_iat_std` | Sample standard deviation of flow IATs (us). | Flow-wide IAT Queue | **Medium** | Sample standard deviation | 0.0 if N_flow_iats <= 1. |
| **39**| `flow_iat_min` | Minimum inter-arrival time across all packets (us). | Flow-wide IAT Queue | **High** | Min delta | Minimum flow-wide inter-arrival time (us). |
| **40**| `flow_bytes_per_sec`| total_bytes / duration_sec (0.0 if delta_t = 0). | Volume & Duration | **Medium** | Rate calculation | Transfer rate in bytes/sec; 0.0 for single-packet flows. |
| **41**| `fwd_packets_per_sec`| N_fwd / duration_sec (0.0 if delta_t = 0). | Count & Duration | **Medium** | Rate calculation | Forward packet rate; 0.0 for single-packet flows. |
| **42**| `bwd_packets_per_sec`| N_bwd / duration_sec (0.0 if delta_t = 0). | Count & Duration | **Medium** | Rate calculation | Backward packet rate; 0.0 for single-packet flows. |
| **43**| `active_mean` | Mean duration of active periods (us) prior to >= 5.0s idle gaps. | Active/Idle State Machine | **Medium** | Burst state machine | Evaluates to 0.0 if no idle gaps occurred. |
| **44**| `active_std` | Sample standard deviation of active bursts (us). | Active/Idle State Machine | **Low** | Sample standard deviation | Evaluates to 0.0 if <= 1 active burst. |
| **45**| `active_max` | Maximum active burst duration (us). | Active/Idle State Machine | **Medium** | Max burst | Evaluates to 0.0 if no idle gaps occurred. |
| **46**| `active_min` | Minimum active burst duration (us). | Active/Idle State Machine | **Medium** | Min burst | Evaluates to 0.0 if no idle gaps occurred. |
| **47**| `idle_std` | Sample standard deviation of idle gap durations (us). | Active/Idle State Machine | **Low** | Sample standard deviation | Evaluates to 0.0 if <= 1 idle gap. |
| **48**| `idle_min` | Minimum idle gap duration (us). | Active/Idle State Machine | **Medium** | Min idle gap | Evaluates to 0.0 if no idle gaps occurred. |

---

## 3. Semantic Differences & Edge Case Analysis

1. **Directionality Assignment**:
   - **Specification**: In CICFlowMeter, the direction of a flow is determined exclusively by the **first packet observed** in the capture file. The source of that packet is defined as `forward_endpoint = (src_ip, src_port)` and destination is `backward_endpoint = (dst_ip, dst_port)`.
   - **Implementation**: Our `FlowAccumulator` locks `forward_endpoint` upon receipt of `first_packet`.
2. **Active vs. Idle State Machine**:
   - **Specification**: An idle state transition occurs whenever delta_t >= 5,000,000 us (5.0s). The time elapsed before this gap is recorded as an active burst.
   - **Nuance**: Short flows with total duration < 5.0s or flows where packets arrive with intervals < 5.0s never transition to idle. For such flows, all 6 active/idle metrics evaluate strictly to 0.0.
3. **TCP Initial Window Sizes**:
   - **Specification**: `init_win_bytes_fwd` captures the TCP window value from the first forward TCP packet. `init_win_bytes_bwd` captures the window from the first backward TCP packet.
   - **Nuance**: For non-TCP flows (UDP) or unidirectional flows with no response, both values must default to -1.0.
4. **Header Length Computations**:
   - **Specification**: `fwd_header_length` and `bwd_header_length` represent the sum of IP headers plus transport headers for forward and backward packets.
   - **Nuance**: In some CICFlowMeter releases, `fwd_header_length` can reflect 32-bit word counts (H * 4) or raw byte counts. We record exact byte lengths (L_IP_hdr + L_TCP_hdr).
