import pandas as pd

from src.dataset import ATTACK_TYPES, CLASSES, generate_dataset
from src.temporal_features import add_temporal_features


def test_phase1b_contains_six_classes_and_ordered_sequences():
    df = generate_dataset(sequences_per_class=3, flows_per_sequence=6, seed=7)
    assert sorted(df["attack_type"].unique()) == sorted(CLASSES)
    assert df["sequence_id"].nunique() == 18
    assert (df.groupby("sequence_id")["flow_index"].apply(lambda s: s.is_monotonic_increasing)).all()
    assert set(ATTACK_TYPES).issubset(set(df["attack_type"]))


def test_temporal_features_preserve_sequence_boundaries():
    df = pd.DataFrame({
        "sequence_id": [0, 0, 1], "flow_index": [0, 1, 0],
        "flow_packets_per_sec": [10, 20, 100], "fwd_iat_mean": [100, 90, 1000],
        "syn_flag_count": [1, 2, 10], "fin_flag_count": [1, 1, 1],
        "packet_length_variance": [10, 20, 40],
    })
    out = add_temporal_features(df, window_size=3)
    row = out[(out.sequence_id == 1) & (out.flow_index == 0)].iloc[0]
    assert row["flow_packets_per_sec_rm"] == 100
