from pathlib import Path
from src.paml_detector_v4 import PAMLDetectorV4
from src.v4_schema import ALL_FEATURES_V4
ROOT=Path(__file__).resolve().parents[1]

def flow():
    return {"flow_duration":63333.0,"fwd_packet_length_mean":84.0,"bwd_packet_length_mean":0.0,"flow_bytes_per_sec":25200.0,"flow_packets_per_sec":300.0,"fwd_iat_mean":3333.0,"bwd_iat_mean":0.0,"protocol_encoded":2.0,"syn_flag_count":0.0,"fin_flag_count":0.0,"packet_length_variance":20.0}

def test_v4_detector_runs_with_20_feature_model():
    d=PAMLDetectorV4(ROOT/'models',window_size=5,attack_threshold=0.5,persistence=1)
    decision,f,i,row=d.predict_flow_timed(flow(),('a','b',2))
    assert 0<=decision.attack_probability<=1
    assert len([k for k in ALL_FEATURES_V4 if k in row])==20
    assert f>=0 and i>=0
