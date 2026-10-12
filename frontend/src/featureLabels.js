// Display labels for the 21 behavioral features (text copied from ml/features.py FEATURE_DESCRIPTIONS).
// Labels only - no data. Unknown feature names fall back to the raw name.
export const FEATURE_LABELS = {
  "flow_duration_s": "Connection duration (seconds)",
  "total_packets": "Total packets in the flow",
  "total_bytes": "Total bytes transferred",
  "packets_per_sec": "Packet rate",
  "bytes_per_sec": "Data rate",
  "fwd_bwd_pkt_ratio": "Outbound-to-inbound packet ratio (traffic asymmetry)",
  "fwd_bwd_byte_ratio": "Outbound-to-inbound byte ratio (data asymmetry)",
  "avg_packet_size": "Average packet size",
  "packet_size_std": "Variability of packet sizes",
  "iat_mean_ms": "Average gap between packets (ms)",
  "iat_std_ms": "Variability of packet timing (ms)",
  "iat_max_s": "Longest pause between packets (seconds)",
  "syn_per_packet": "Share of packets carrying SYN (connection setup)",
  "rst_per_packet": "Share of packets carrying RST (connection reset)",
  "fin_per_packet": "Share of packets carrying FIN (connection close)",
  "psh_per_packet": "Share of packets carrying PSH (push data)",
  "ack_per_packet": "Share of packets carrying ACK",
  "init_win_fwd": "Initial TCP window size, outbound",
  "init_win_bwd": "Initial TCP window size, inbound",
  "active_mean_s": "Average active period (seconds)",
  "idle_mean_s": "Average idle period (seconds)"
};
