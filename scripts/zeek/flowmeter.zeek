# scripts/zeek/flowmeter.zeek
# Packet-level feature extraction for network flows in Zeek
# Extracts the canonical 48 CICFlowMeter features per connection for ML compatibility research.

module FlowMeter;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id_orig_h: addr &log;
        id_orig_p: port &log;
        id_resp_h: addr &log;
        id_resp_p: port &log;
        proto: string &log;
        duration: interval &log;

        # 48 Canonical Model Features (FlowFeaturesInput)
        psh_flag_count: count &log;
        bwd_packet_length_mean: double &log;
        min_seg_size_fwd: count &log;
        bwd_packet_length_std: double &log;
        bwd_packet_length_min: count &log;
        max_packet_length: count &log;
        destination_port: count &log;
        ack_flag_count: count &log;
        packet_length_mean: double &log;
        fwd_iat_std: double &log;

        idle_min: double &log;
        init_win_bytes_fwd: double &log;
        packet_length_variance: double &log;
        min_packet_length: count &log;
        fwd_packet_length_max: count &log;
        act_data_pkt_fwd: count &log;
        flow_iat_std: double &log;
        total_forward_packets: count &log;
        down_up_ratio: double &log;
        flow_iat_mean: double &log;

        avg_fwd_segment_size: double &log;
        fwd_header_length: count &log;
        bwd_header_length: count &log;
        fwd_iat_total: double &log;
        fin_flag_count: count &log;
        bwd_iat_total: double &log;
        fwd_packets_per_sec: double &log;
        urg_flag_count: count &log;
        init_win_bytes_bwd: double &log;
        fwd_iat_mean: double &log;

        fwd_packet_length_min: count &log;
        total_forward_bytes: count &log;
        bwd_packets_per_sec: double &log;
        syn_flag_count: count &log;
        bwd_iat_max: double &log;
        bwd_iat_mean: double &log;
        bwd_iat_std: double &log;
        active_mean: double &log;
        flow_bytes_per_sec: double &log;
        active_min: double &log;

        flow_iat_min: double &log;
        active_max: double &log;
        fwd_iat_min: double &log;
        idle_std: double &log;
        bwd_iat_min: double &log;
        active_std: double &log;
        fwd_urg_flags: count &log;
        ece_flag_count: count &log;
    };
}

# Internal accumulator state for a connection
type FlowState: record {
    start_time: time;
    last_time: time;
    last_fwd_time: time;
    last_bwd_time: time;
    has_fwd_time: bool;
    has_bwd_time: bool;

    # Counts and byte totals
    fwd_pkts: count;
    bwd_pkts: count;
    fwd_bytes: count;
    bwd_bytes: count;
    fwd_hdr_bytes: count;
    bwd_hdr_bytes: count;
    act_data_fwd: count;
    min_seg_size_fwd: count;

    # Packet length bounds
    min_pkt_len: count;
    max_pkt_len: count;
    fwd_min_len: count;
    fwd_max_len: count;
    bwd_min_len: count;
    bwd_max_len: count;

    # Welford state for all packet lengths
    len_count: count;
    len_mean: double;
    len_m2: double;

    # Welford state for backward packet lengths
    bwd_len_count: count;
    bwd_len_mean: double;
    bwd_len_m2: double;

    # Welford state for flow IAT (microseconds)
    flow_iat_count: count;
    flow_iat_mean: double;
    flow_iat_m2: double;
    flow_iat_min: double;

    # Welford state for forward IAT (microseconds)
    fwd_iat_count: count;
    fwd_iat_mean: double;
    fwd_iat_m2: double;
    fwd_iat_min: double;
    fwd_iat_total: double;

    # Welford state for backward IAT (microseconds)
    bwd_iat_count: count;
    bwd_iat_mean: double;
    bwd_iat_m2: double;
    bwd_iat_min: double;
    bwd_iat_max: double;
    bwd_iat_total: double;

    # TCP Flags
    fin_cnt: count;
    syn_cnt: count;
    rst_cnt: count;
    psh_cnt: count;
    ack_cnt: count;
    urg_cnt: count;
    ece_cnt: count;
    fwd_urg_cnt: count;

    # TCP Window advertisements
    init_win_fwd: double;
    init_win_bwd: double;
    has_win_fwd: bool;
    has_win_bwd: bool;

    # Active / Idle state machine (5.0s threshold = 5,000,000 us)
    active_start: time;
    active_last: time;
    active_count: count;
    active_mean: double;
    active_m2: double;
    active_min: double;
    active_max: double;

    idle_count: count;
    idle_mean: double;
    idle_m2: double;
    idle_min: double;
};

# Global table of active flow states indexed by connection UID
global active_flows: table[string] of FlowState;

const IDLE_THRESHOLD = 5.0sec;

event zeek_init() {
    Log::create_stream(FlowMeter::LOG, [$columns=Info, $path="flowmeter"]);
}

function init_flow_state(t: time): FlowState {
    local s: FlowState;
    s$start_time = t;
    s$last_time = t;
    s$last_fwd_time = t;
    s$last_bwd_time = t;
    s$has_fwd_time = F;
    s$has_bwd_time = F;

    s$fwd_pkts = 0;
    s$bwd_pkts = 0;
    s$fwd_bytes = 0;
    s$bwd_bytes = 0;
    s$fwd_hdr_bytes = 0;
    s$bwd_hdr_bytes = 0;
    s$act_data_fwd = 0;
    s$min_seg_size_fwd = 0;

    s$min_pkt_len = 65535;
    s$max_pkt_len = 0;
    s$fwd_min_len = 65535;
    s$fwd_max_len = 0;
    s$bwd_min_len = 65535;
    s$bwd_max_len = 0;

    s$len_count = 0;
    s$len_mean = 0.0;
    s$len_m2 = 0.0;

    s$bwd_len_count = 0;
    s$bwd_len_mean = 0.0;
    s$bwd_len_m2 = 0.0;

    s$flow_iat_count = 0;
    s$flow_iat_mean = 0.0;
    s$flow_iat_m2 = 0.0;
    s$flow_iat_min = 1.0e12;

    s$fwd_iat_count = 0;
    s$fwd_iat_mean = 0.0;
    s$fwd_iat_m2 = 0.0;
    s$fwd_iat_min = 1.0e12;
    s$fwd_iat_total = 0.0;

    s$bwd_iat_count = 0;
    s$bwd_iat_mean = 0.0;
    s$bwd_iat_m2 = 0.0;
    s$bwd_iat_min = 1.0e12;
    s$bwd_iat_max = 0.0;
    s$bwd_iat_total = 0.0;

    s$fin_cnt = 0;
    s$syn_cnt = 0;
    s$rst_cnt = 0;
    s$psh_cnt = 0;
    s$ack_cnt = 0;
    s$urg_cnt = 0;
    s$ece_cnt = 0;
    s$fwd_urg_cnt = 0;

    s$init_win_fwd = -1.0;
    s$init_win_bwd = -1.0;
    s$has_win_fwd = F;
    s$has_win_bwd = F;

    s$active_start = t;
    s$active_last = t;
    s$active_count = 0;
    s$active_mean = 0.0;
    s$active_m2 = 0.0;
    s$active_min = 1.0e12;
    s$active_max = 0.0;

    s$idle_count = 0;
    s$idle_mean = 0.0;
    s$idle_m2 = 0.0;
    s$idle_min = 1.0e12;

    return s;
}

# Update Welford online variance
function update_welford(count_val: count, mean_val: double, m2_val: double, new_val: double): vector of double {
    local n = count_val + 1;
    local delta = new_val - mean_val;
    local new_mean = mean_val + delta / n;
    local delta2 = new_val - new_mean;
    local new_m2 = m2_val + delta * delta2;
    return vector(new_mean, new_m2);
}

event new_packet(c: connection, p: pkt_hdr) {
    local uid = c$uid;
    local is_orig = (p$is_orig);
    local pkt_len = p$payload_len;
    local cur_time = p$ts;

    if (uid !in active_flows) {
        active_flows[uid] = init_flow_state(cur_time);
    }
    local s = active_flows[uid];

    # Active / Idle state transitions
    if (s$len_count > 0) {
        local gap = cur_time - s$active_last;
        if (gap > IDLE_THRESHOLD) {
            # Flush previous active period
            local act_dur = interval_to_double(s$active_last - s$active_start) * 1000000.0;
            if (act_dur > 0.0) {
                local act_res = update_welford(s$active_count, s$active_mean, s$active_m2, act_dur);
                s$active_count = s$active_count + 1;
                s$active_mean = act_res[0];
                s$active_m2 = act_res[1];
                if (act_dur < s$active_min) s$active_min = act_dur;
                if (act_dur > s$active_max) s$active_max = act_dur;
            }
            # Record idle gap
            local idle_dur = interval_to_double(gap) * 1000000.0;
            local idle_res = update_welford(s$idle_count, s$idle_mean, s$idle_m2, idle_dur);
            s$idle_count = s$idle_count + 1;
            s$idle_mean = idle_res[0];
            s$idle_m2 = idle_res[1];
            if (idle_dur < s$idle_min) s$idle_min = idle_dur;

            s$active_start = cur_time;
        }
    }
    s$active_last = cur_time;

    # Flow-wide IAT
    if (s$len_count > 0) {
        local flow_iat = interval_to_double(cur_time - s$last_time) * 1000000.0;
        if (flow_iat < 0.0) flow_iat = 0.0;
        local fi_res = update_welford(s$flow_iat_count, s$flow_iat_mean, s$flow_iat_m2, flow_iat);
        s$flow_iat_count = s$flow_iat_count + 1;
        s$flow_iat_mean = fi_res[0];
        s$flow_iat_m2 = fi_res[1];
        if (flow_iat < s$flow_iat_min) s$flow_iat_min = flow_iat;
    }
    s$last_time = cur_time;

    # Overall packet length statistics
    local pl_res = update_welford(s$len_count, s$len_mean, s$len_m2, pkt_len + 0.0);
    s$len_count = s$len_count + 1;
    s$len_mean = pl_res[0];
    s$len_m2 = pl_res[1];
    if (pkt_len < s$min_pkt_len) s$min_pkt_len = pkt_len;
    if (pkt_len > s$max_pkt_len) s$max_pkt_len = pkt_len;

    # Direction-specific updates
    if (is_orig) {
        s$fwd_pkts = s$fwd_pkts + 1;
        s$fwd_bytes = s$fwd_bytes + pkt_len;
        if (pkt_len > 0) s$act_data_fwd = s$act_data_fwd + 1;
        if (pkt_len < s$fwd_min_len) s$fwd_min_len = pkt_len;
        if (pkt_len > s$fwd_max_len) s$fwd_max_len = pkt_len;

        if (s$has_fwd_time) {
            local fwd_iat = interval_to_double(cur_time - s$last_fwd_time) * 1000000.0;
            if (fwd_iat < 0.0) fwd_iat = 0.0;
            local fwd_res = update_welford(s$fwd_iat_count, s$fwd_iat_mean, s$fwd_iat_m2, fwd_iat);
            s$fwd_iat_count = s$fwd_iat_count + 1;
            s$fwd_iat_mean = fwd_res[0];
            s$fwd_iat_m2 = fwd_res[1];
            if (fwd_iat < s$fwd_iat_min) s$fwd_iat_min = fwd_iat;
            s$fwd_iat_total = s$fwd_iat_total + fwd_iat;
        }
        s$last_fwd_time = cur_time;
        s$has_fwd_time = T;

        # TCP Header length
        if (p?$tcp) {
            local fwd_hl = p$tcp$data_offset * 4;
            s$fwd_hdr_bytes = s$fwd_hdr_bytes + fwd_hl;
            if (s$min_seg_size_fwd == 0 || fwd_hl < s$min_seg_size_fwd) {
                s$min_seg_size_fwd = fwd_hl;
            }
            if (!s$has_win_fwd) {
                s$init_win_fwd = p$tcp$win + 0.0;
                s$has_win_fwd = T;
            }
        }
    } else {
        s$bwd_pkts = s$bwd_pkts + 1;
        s$bwd_bytes = s$bwd_bytes + pkt_len;
        if (pkt_len < s$bwd_min_len) s$bwd_min_len = pkt_len;
        if (pkt_len > s$bwd_max_len) s$bwd_max_len = pkt_len;

        # Backward packet lengths Welford
        local bl_res = update_welford(s$bwd_len_count, s$bwd_len_mean, s$bwd_len_m2, pkt_len + 0.0);
        s$bwd_len_count = s$bwd_len_count + 1;
        s$bwd_len_mean = bl_res[0];
        s$bwd_len_m2 = bl_res[1];

        if (s$has_bwd_time) {
            local bwd_iat = interval_to_double(cur_time - s$last_bwd_time) * 1000000.0;
            if (bwd_iat < 0.0) bwd_iat = 0.0;
            local bwd_res = update_welford(s$bwd_iat_count, s$bwd_iat_mean, s$bwd_iat_m2, bwd_iat);
            s$bwd_iat_count = s$bwd_iat_count + 1;
            s$bwd_iat_mean = bwd_res[0];
            s$bwd_iat_m2 = bwd_res[1];
            if (bwd_iat < s$bwd_iat_min) s$bwd_iat_min = bwd_iat;
            if (bwd_iat > s$bwd_iat_max) s$bwd_iat_max = bwd_iat;
            s$bwd_iat_total = s$bwd_iat_total + bwd_iat;
        }
        s$last_bwd_time = cur_time;
        s$has_bwd_time = T;

        if (p?$tcp) {
            s$bwd_hdr_bytes = s$bwd_hdr_bytes + (p$tcp$data_offset * 4);
            if (!s$has_win_bwd) {
                s$init_win_bwd = p$tcp$win + 0.0;
                s$has_win_bwd = T;
            }
        }
    }

    # TCP Flags inspection
    if (p?$tcp) {
        local flags = p$tcp$flags;
        if ((flags & 0x01) != 0) s$fin_cnt = s$fin_cnt + 1;
        if ((flags & 0x02) != 0) s$syn_cnt = s$syn_cnt + 1;
        if ((flags & 0x04) != 0) s$rst_cnt = s$rst_cnt + 1;
        if ((flags & 0x08) != 0) s$psh_cnt = s$psh_cnt + 1;
        if ((flags & 0x10) != 0) s$ack_cnt = s$ack_cnt + 1;
        if ((flags & 0x20) != 0) {
            s$urg_cnt = s$urg_cnt + 1;
            if (is_orig) s$fwd_urg_cnt = s$fwd_urg_cnt + 1;
        }
        if ((flags & 0x40) != 0) s$ece_cnt = s$ece_cnt + 1;
    }

    active_flows[uid] = s;
}

event connection_state_remove(c: connection) {
    local uid = c$uid;
    if (uid !in active_flows) return;

    local s = active_flows[uid];
    local dur_sec = interval_to_double(s$last_time - s$start_time);
    if (dur_sec < 0.0) dur_sec = 0.0;

    # Flush final active period
    local act_dur = interval_to_double(s$active_last - s$active_start) * 1000000.0;
    if (act_dur > 0.0) {
        local act_res = update_welford(s$active_count, s$active_mean, s$active_m2, act_dur);
        s$active_count = s$active_count + 1;
        s$active_mean = act_res[0];
        s$active_m2 = act_res[1];
        if (act_dur < s$active_min) s$active_min = act_dur;
        if (act_dur > s$active_max) s$active_max = act_dur;
    }

    # Rates
    local total_bytes = s$fwd_bytes + s$bwd_bytes;
    local flow_bytes_sec = dur_sec > 0.0 ? (total_bytes + 0.0) / dur_sec : 0.0;
    local fwd_pkts_sec = dur_sec > 0.0 ? (s$fwd_pkts + 0.0) / dur_sec : 0.0;
    local bwd_pkts_sec = dur_sec > 0.0 ? (s$bwd_pkts + 0.0) / dur_sec : 0.0;
    local down_up = s$fwd_pkts > 0 ? (s$bwd_pkts + 0.0) / (s$fwd_pkts + 0.0) : 0.0;
    local avg_fwd_seg = s$fwd_pkts > 0 ? (s$fwd_bytes + 0.0) / (s$fwd_pkts + 0.0) : 0.0;

    # Standard deviations and variances (sample ddof=1)
    local len_var = s$len_count > 1 ? s$len_m2 / (s$len_count - 1.0) : 0.0;
    local len_std = sqrt(len_var);
    local bwd_len_var = s$bwd_len_count > 1 ? s$bwd_len_m2 / (s$bwd_len_count - 1.0) : 0.0;
    local bwd_len_std = sqrt(bwd_len_var);

    local flow_iat_var = s$flow_iat_count > 1 ? s$flow_iat_m2 / (s$flow_iat_count - 1.0) : 0.0;
    local flow_iat_std = sqrt(flow_iat_var);
    local fwd_iat_var = s$fwd_iat_count > 1 ? s$fwd_iat_m2 / (s$fwd_iat_count - 1.0) : 0.0;
    local fwd_iat_std = sqrt(fwd_iat_var);
    local bwd_iat_var = s$bwd_iat_count > 1 ? s$bwd_iat_m2 / (s$bwd_iat_count - 1.0) : 0.0;
    local bwd_iat_std = sqrt(bwd_iat_var);

    local act_var = s$active_count > 1 ? s$active_m2 / (s$active_count - 1.0) : 0.0;
    local act_std = sqrt(act_var);
    local idle_var = s$idle_count > 1 ? s$idle_m2 / (s$idle_count - 1.0) : 0.0;
    local idle_std = sqrt(idle_var);

    local rec: Info;
    rec$ts = s$start_time;
    rec$uid = uid;
    rec$id_orig_h = c$id$orig_h;
    rec$id_orig_p = c$id$orig_p;
    rec$id_resp_h = c$id$resp_h;
    rec$id_resp_p = c$id$resp_p;
    rec$proto = get_port_transport_proto(c$id$resp_p) == tcp ? "tcp" : (get_port_transport_proto(c$id$resp_p) == udp ? "udp" : "icmp");
    rec$duration = s$last_time - s$start_time;

    # 48 features populated
    rec$psh_flag_count = s$psh_cnt;
    rec$bwd_packet_length_mean = s$bwd_len_mean;
    rec$min_seg_size_fwd = s$min_seg_size_fwd > 0 ? s$min_seg_size_fwd : (rec$proto == "tcp" ? 20 : 8);
    rec$bwd_packet_length_std = bwd_len_std;
    rec$bwd_packet_length_min = s$bwd_len_count > 0 ? s$bwd_min_len : 0;
    rec$max_packet_length = s$len_count > 0 ? s$max_pkt_len : 0;
    rec$destination_port = port_to_count(c$id$resp_p);
    rec$ack_flag_count = s$ack_cnt;
    rec$packet_length_mean = s$len_mean;
    rec$fwd_iat_std = fwd_iat_std;

    rec$idle_min = s$idle_count > 0 ? s$idle_min : 0.0;
    rec$init_win_bytes_fwd = s$init_win_fwd;
    rec$packet_length_variance = len_var;
    rec$min_packet_length = s$len_count > 0 ? s$min_pkt_len : 0;
    rec$fwd_packet_length_max = s$fwd_pkts > 0 ? s$fwd_max_len : 0;
    rec$act_data_pkt_fwd = s$act_data_fwd;
    rec$flow_iat_std = flow_iat_std;
    rec$total_forward_packets = s$fwd_pkts;
    rec$down_up_ratio = down_up;
    rec$flow_iat_mean = s$flow_iat_mean;

    rec$avg_fwd_segment_size = avg_fwd_seg;
    rec$fwd_header_length = s$fwd_hdr_bytes;
    rec$bwd_header_length = s$bwd_hdr_bytes;
    rec$fwd_iat_total = s$fwd_iat_total;
    rec$fin_flag_count = s$fin_cnt;
    rec$bwd_iat_total = s$bwd_iat_total;
    rec$fwd_packets_per_sec = fwd_pkts_sec;
    rec$urg_flag_count = s$urg_cnt;
    rec$init_win_bytes_bwd = s$init_win_bwd;
    rec$fwd_iat_mean = s$fwd_iat_mean;

    rec$fwd_packet_length_min = s$fwd_pkts > 0 ? s$fwd_min_len : 0;
    rec$total_forward_bytes = s$fwd_bytes;
    rec$bwd_packets_per_sec = bwd_pkts_sec;
    rec$syn_flag_count = s$syn_cnt;
    rec$bwd_iat_max = s$bwd_iat_max;
    rec$bwd_iat_mean = s$bwd_iat_mean;
    rec$bwd_iat_std = bwd_iat_std;
    rec$active_mean = s$active_mean;
    rec$flow_bytes_per_sec = flow_bytes_sec;
    rec$active_min = s$active_count > 0 ? s$active_min : 0.0;

    rec$flow_iat_min = s$flow_iat_count > 0 ? s$flow_iat_min : 0.0;
    rec$active_max = s$active_max;
    rec$fwd_iat_min = s$fwd_iat_count > 0 ? s$fwd_iat_min : 0.0;
    rec$idle_std = idle_std;
    rec$bwd_iat_min = s$bwd_iat_count > 0 ? s$bwd_iat_min : 0.0;
    rec$active_std = act_std;
    rec$fwd_urg_flags = s$fwd_urg_cnt;
    rec$ece_flag_count = s$ece_cnt;

    Log::write(FlowMeter::LOG, rec);
    delete active_flows[uid];
}
