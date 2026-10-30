"""Compare accelerated expiry against the actual project's online table."""
import random
from controller.flow_features import OnlineFlowTable
from fast_flow_table import FastFlowTable


def test_optimised_table_matches_online_flow_table():
    rng=random.Random(9321)
    original=OnlineFlowTable(.75,20); fast=FastFlowTable(.75,20)
    all_original=[]; all_fast=[]; now=0.0
    for i in range(6000):
        now += rng.choice((0.0,.00001,.005,.04,.8))
        source=f'10.0.{rng.randrange(3)}.{rng.randrange(20)}'
        kwargs=dict(now=now,src_port=rng.randrange(2),dst_port=502,
                    ground_truth='benign',run_id='test')
        arguments=(source,'10.1.1.1','TCP',rng.randrange(60,1200),rng.random()<.3,False,False)
        a=original.observe(*arguments,**kwargs)
        b=fast.observe(*arguments,**kwargs)
        all_original.extend(a); all_fast.extend(b)
        assert sorted(a,key=lambda x:x['flow_id']) == sorted(b,key=lambda x:x['flow_id'])
    all_original.extend(original.expire(force=True)); all_fast.extend(fast.expire(force=True))
    assert sorted(all_original,key=lambda x:x['flow_id']) == sorted(all_fast,key=lambda x:x['flow_id'])


def test_pcap_packet_parser_rejects_non_ip_and_preserves_transport():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from inspect_captures import parse_packet
    packet=bytes(Ether()/IP(src='10.1.2.3',dst='10.2.3.4')/TCP(sport=12,dport=502,flags='S'))
    assert parse_packet(packet) == ('ok','10.1.2.3','10.2.3.4',6,12,502,2)
    assert parse_packet(b'\x00'*13) is None


def test_replay_probability_matches_deployed_detector():
    from collections import defaultdict, deque
    from pathlib import Path
    import numpy as np
    from src.temporal_features_v4 import build_temporal_row
    from src.v4_schema import ALL_FEATURES_V4
    from src.paml_detector_v4 import PAMLDetectorV4
    root=Path(__file__).resolve().parents[3]/'v4'
    detector=PAMLDetectorV4(root/'models_live',window_size=5,attack_threshold=.85,persistence=1)
    flows=[]; keys=[]
    for i in range(30):
        flows.append(dict(flow_duration=20000+i*100,fwd_packet_length_mean=100+i,
            bwd_packet_length_mean=0,flow_bytes_per_sec=8000+i*100,
            flow_packets_per_sec=200+i*7,fwd_iat_mean=1000+i*20,bwd_iat_mean=0,
            protocol_encoded=i%3,syn_flag_count=i%4,fin_flag_count=i%2,packet_length_variance=i*5))
        keys.append(('stream',i%3))
    decisions=detector.predict_flows_timed(flows,keys)
    histories=defaultdict(lambda:deque(maxlen=5))
    features=[build_temporal_row(flow,histories[key]) for flow,key in zip(flows,keys)]
    x=np.array([[row[name] for name in ALL_FEATURES_V4] for row in features])
    probabilities=detector.binary_model.predict_proba(detector.scaler.transform(x))[:,list(detector.binary_model.classes_).index(1)]
    np.testing.assert_allclose(probabilities,[d[0].attack_probability for d in decisions],rtol=0,atol=1e-14)
    assert np.array_equal(probabilities>=.85,[d[0].is_attack for d in decisions])
