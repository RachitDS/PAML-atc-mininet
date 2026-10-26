from controller.flow_features import OnlineFlowTable
from controller.flow_features import FlowStats
import pytest


def test_packet_window_emits_and_has_model_schema():
    table = OnlineFlowTable(max_packets=5)
    rows = []
    for i in range(5):
        rows.extend(table.observe('10.0.0.40', '10.0.0.10', 'UDP', 1000, now=10 + i * 0.01))
    assert len(rows) == 1
    expected = {
        'flow_duration', 'fwd_packet_length_mean', 'bwd_packet_length_mean',
        'flow_bytes_per_sec', 'flow_packets_per_sec', 'fwd_iat_mean',
        'bwd_iat_mean', 'active_mean', 'idle_mean', 'fwd_packets_per_sec',
        'bwd_packets_per_sec', 'packet_length_variance', 'fin_flag_count',
        'syn_flag_count', 'rst_flag_count', 'protocol_encoded', 'down_up_ratio'
    }
    assert expected.issubset(rows[0])


def test_idle_expiry():
    table = OnlineFlowTable(idle_timeout=0.5, max_packets=100)
    table.observe('10.0.0.40', '10.0.0.10', 'ICMP', 64, now=1.0)
    rows = table.expire(now=1.6)
    assert len(rows) == 1


@pytest.mark.parametrize('forward',[True,False])
def test_iat_is_independent_of_zero_or_nonzero_clock_origin(forward):
    results=[]
    for origin in [0,100]:
        stats=FlowStats(first_ts=origin,last_ts=origin)
        for i in range(3):
            stats.add(origin+i*.01,100,forward,False,False,False)
        results.append(stats.to_features(2))
    assert results[0]==pytest.approx(results[1])
    name='fwd_iat_mean' if forward else 'bwd_iat_mean'
    assert results[0][name]==pytest.approx(10000)
