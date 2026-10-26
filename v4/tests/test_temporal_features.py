import pandas as pd

from src.temporal_features import add_temporal_features


def test_temporal_features_respect_sequence_boundaries():
    df = pd.DataFrame({
        "sequence_id": [0, 0, 0, 1, 1],
        "flow_index": [0, 1, 2, 0, 1],
        "flow_packets_per_sec": [10, 20, 30, 100, 200],
        "fwd_iat_mean": [100, 90, 80, 1000, 900],
        "syn_flag_count": [1, 2, 3, 10, 20],
        "fin_flag_count": [1, 1, 1, 1, 1],
        "packet_length_variance": [10, 20, 30, 40, 50],
    })
    out = add_temporal_features(df, window_size=3)
    # First flow of sequence 1 must not include sequence 0 values.
    first_seq1 = out[(out.sequence_id == 1) & (out.flow_index == 0)].iloc[0]
    assert first_seq1["flow_packets_per_sec_rm"] == 100
