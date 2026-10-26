import pandas as pd
import pytest

from src.packet_accounting import PacketAccounting, pdr
from phase6b3_experiment import validate_packet_accounting


def test_offered_packets_are_explicit_and_integer():
    assert PacketAccounting.offered_packets(1000, 2_000_000) == 2000


def test_delivered_never_exceeds_offered():
    a = PacketAccounting(1000)
    out = a.record_flow(
        label=1, offered_pps=5000, flow_duration_us=1_000_000,
        rate_limit_pps=100, drop_probability=0.5, capacity_factor=1.0,
    )
    assert out.delivered_packets <= out.offered_packets
    assert out.dropped_packets >= 0


def test_pdr_uses_counts_not_reported_pdr():
    assert pdr(90, 100) == 0.9


def test_validation_rejects_inconsistent_overall_pdr():
    df = pd.DataFrame([{
        "benign_offered_packets": 100,
        "benign_delivered_packets": 90,
        "attack_offered_packets": 100,
        "attack_delivered_packets": 20,
        "total_offered_packets": 200,
        "total_delivered_packets": 110,
        "overall_pdr": 0.9,
    }])
    issues = validate_packet_accounting(df)
    assert "OVERALL_PDR_NOT_FROM_PACKET_COUNTS" in issues


def test_validation_accepts_consistent_counts():
    df = pd.DataFrame([{
        "benign_offered_packets": 100,
        "benign_delivered_packets": 90,
        "attack_offered_packets": 100,
        "attack_delivered_packets": 20,
        "total_offered_packets": 200,
        "total_delivered_packets": 110,
        "overall_pdr": 0.55,
    }])
    assert validate_packet_accounting(df) == []
