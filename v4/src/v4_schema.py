"""PAML-ATC V4 deployment-aligned 20-feature schema.

The V4 model intentionally separates the eight base features used by the
PAML-style model from twelve temporal features.  SYN/FIN/packet-length
variance remain auxiliary online measurements used to construct temporal
features, but are not silently counted as additional model inputs.
"""
BASE_FEATURES_V4 = [
    "flow_duration",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "protocol_encoded",
]

TEMPORAL_FEATURES_V4 = [
    "flow_packets_per_sec_rm",
    "flow_packets_per_sec_rs",
    "flow_packets_per_sec_delta",
    "fwd_iat_mean_rm",
    "fwd_iat_mean_rs",
    "fwd_iat_mean_delta",
    "syn_flag_count_rm",
    "syn_flag_count_rs",
    "syn_flag_count_delta",
    "syn_fin_ratio",
    "packet_variability_inverse",
    "iat_acceleration",
]

ALL_FEATURES_V4 = BASE_FEATURES_V4 + TEMPORAL_FEATURES_V4
assert len(BASE_FEATURES_V4) == 8
assert len(TEMPORAL_FEATURES_V4) == 12
assert len(ALL_FEATURES_V4) == 20
