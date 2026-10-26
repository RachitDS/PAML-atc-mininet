from pathlib import Path
import numpy as np
from src.paml_detector_v4 import PAMLDetectorV4
from src.v4_schema import BASE_FEATURES_V4


def test_batch_preserves_features_probabilities_and_persistence():
    models = Path(__file__).resolve().parents[1] / 'models'
    sequential = PAMLDetectorV4(models, persistence=2)
    batched = PAMLDetectorV4(models, persistence=2)
    flows = []
    for i in range(8):
        flow = {k: float(10 + i) for k in BASE_FEATURES_V4}
        flow.update(protocol_encoded=2, syn_flag_count=0, fin_flag_count=0,
                    packet_length_variance=100+i)
        flows.append(flow)
    keys = ['a', 'b'] * 4
    expected = [sequential.predict_flow_timed(flow, key) for flow, key in zip(flows, keys)]
    actual = batched.predict_flows_timed(flows, keys)
    for e, a in zip(expected, actual):
        assert e[0] == a[0]
        assert e[3] == a[3]
