import csv
import controller.metrics as metrics_module
from src.v4_schema import ALL_FEATURES_V4


def test_live_feature_logging_excludes_string_flow_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics_module, '__file__', str(tmp_path / 'controller/metrics.py'))
    metrics = metrics_module.ControllerMetrics()
    row = {name: 1.25 for name in ALL_FEATURES_V4}
    row.update(src_ip='10.0.0.40', dst_ip='10.0.0.10', protocol='ICMP')
    metrics.decision(dpid=1, src_ip='10.0.0.40', dst_ip='10.0.0.10', protocol='ICMP',
                     category='attack', state='ATTACK', attack_probability=.9,
                     attack_type='ICMP_Flood', action='DROP', feature_ms=.2,
                     inference_ms=4, flow_mod_ms=5, total_handler_ms=6, feature_row=row)
    with metrics.feature_log_path.open(newline='') as f:
        records = list(csv.DictReader(f))
    assert len(records) == 1
    assert list(records[0])[7:27] == ALL_FEATURES_V4
    assert records[0]['src_ip'] == '10.0.0.40'
    assert all(float(records[0][k]) == 1.25 for k in ALL_FEATURES_V4)
