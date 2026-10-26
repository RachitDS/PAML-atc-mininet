import csv
import json
from types import SimpleNamespace
import pytest
from controller.flow_features import OnlineFlowTable
from controller.ground_truth import GroundTruth
import controller.metrics as metrics_module


def test_expired_attack_keeps_identity_when_benign_packet_arrives():
    table = OnlineFlowTable(idle_timeout=.5, max_packets=2)
    table.observe("attacker", "plc", "ICMP", 100, now=1,
                  ground_truth="attack", run_id="r1")
    expired = table.observe("legitimate", "plc", "UDP", 200, now=2,
                            ground_truth="benign", run_id="r1", src_port=50, dst_port=60)
    current = table.observe("legitimate", "plc", "UDP", 200, now=2.1,
                            ground_truth="benign", run_id="r1", src_port=50, dst_port=60)
    assert [(f["src_ip"], f["ground_truth"], f["protocol"]) for f in expired + current] == [
        ("attacker", "attack", "ICMP"), ("legitimate", "benign", "UDP")]
    assert len({f["flow_id"] for f in expired + current}) == 2
    assert table.expire(force=True) == []


def test_switch_and_port_identity_are_independent():
    table = OnlineFlowTable(max_packets=2)
    for dpid, port in [(1, 10), (2, 10), (1, 11)]:
        assert table.observe("a", "b", "TCP", 64, now=1,
                             observation_id=dpid, src_port=port) == []
    rows = table.expire(force=True)
    assert len(rows) == 3
    assert all(r["packet_count"] == 1 for r in rows)


def test_truth_is_manifest_owned_and_unknown_is_explicit(tmp_path):
    path = tmp_path / "truth.json"
    path.write_text(json.dumps(dict(run_id="run", flows=[dict(src_ip="a", dst_ip="b",
        protocol="ICMP", ground_truth="attack")])))
    truth = GroundTruth(path)
    assert truth.lookup("a", "b", "ICMP") == ("attack", "run")
    assert truth.lookup("b", "a", "ICMP") == ("unknown", "run")


def test_unknown_does_not_count_as_true_negative(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics_module, "__file__", str(tmp_path / "controller/metrics.py"))
    metrics = metrics_module.ControllerMetrics()
    metrics.decision(dpid=1, src_ip="a", dst_ip="b", protocol="ICMP", category="unknown",
        state="BENIGN", attack_probability=.1, attack_type="Benign", action="FORWARD",
        feature_ms=0, inference_ms=0, flow_mod_ms=None, total_handler_ms=0,
        flow_metadata=dict(flow_id="unique", run_id="run"))
    assert metrics.summary()["paml_decisions"] == 0
    with metrics.events_path.open() as f:
        row = next(csv.DictReader(f))
    assert row["flow_id"] == "unique"
    assert row["evaluation_eligible"] == "0"


def test_all_expired_flows_are_scored_with_their_own_truth(tmp_path, monkeypatch):
    from controller.auditable_controller import AuditableController
    monkeypatch.setattr(metrics_module, "__file__", str(tmp_path / "controller/metrics.py"))
    table = OnlineFlowTable(max_packets=20)
    table.observe("a", "p", "ICMP", 100, now=1, ground_truth="attack", run_id="r")
    table.observe("b", "p", "UDP", 200, now=1, ground_truth="benign", run_id="r")
    fake = SimpleNamespace(mode="FIXED", datapaths={}, metrics=metrics_module.ControllerMetrics())
    AuditableController.process_flows(fake, table.expire(force=True))
    with fake.metrics.events_path.open() as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert {(r["src_ip"], r["ground_truth"]) for r in rows} == {("a", "attack"), ("b", "benign")}
    assert len({r["flow_id"] for r in rows}) == 2


def test_unlabeled_request_is_still_observed_without_a_truth_dependency():
    from controller.auditable_controller import AuditableController
    from ryu.lib.packet import packet, ethernet, ipv4, icmp
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=0x0800))
    pkt.add_protocol(ipv4.ipv4(src='10.0.0.99', dst='10.0.0.10', proto=1))
    pkt.add_protocol(icmp.icmp(type_=8, data=icmp.echo(id_=1, seq=1, data=b'test')))
    pkt.serialize()
    table = OnlineFlowTable(max_packets=20)
    fake = SimpleNamespace(mode='MONITOR', observation_id=1, protected_ips={'10.0.0.10'},
        truth=GroundTruth(), current_run='unregistered', observed_packets=0,
        metrics=SimpleNamespace(packet_in=lambda label: None), packet_log=None,
        pending=[], flows=table)
    ev = SimpleNamespace(msg=SimpleNamespace(datapath=SimpleNamespace(id=1), data=bytes(pkt.data)))
    AuditableController.packet_in_handler(fake, ev)
    flow=table.expire(force=True)[0]
    assert flow['ground_truth']=='unknown'
    assert flow['src_ip']=='10.0.0.99'


def test_standard_ryu_entrypoint_loads_corrected_controller():
    from pathlib import Path
    from ryu.base import app_manager
    from controller.auditable_controller import AuditableController
    manager=app_manager.AppManager()
    loaded=manager.load_app(str(Path(__file__).resolve().parents[1]/'controller/ryu_paml_controller.py'))
    assert issubclass(loaded,AuditableController)


@pytest.mark.parametrize('mode',['NONE','FIXED'])
def test_baseline_initialization_never_loads_models(mode,tmp_path,monkeypatch):
    import joblib
    import controller.auditable_controller as module
    monkeypatch.setenv('PAML_MODE',mode)
    monkeypatch.delenv('PAML_PACKET_LOG',raising=False)
    monkeypatch.setattr(module.hub,'spawn',lambda callback:None)
    monkeypatch.setattr(metrics_module,'__file__',str(tmp_path/'controller/metrics.py'))
    def forbidden_load(*args,**kwargs):
        pytest.fail('Baseline attempted to load a trained model')
    monkeypatch.setattr(joblib,'load',forbidden_load)
    app=module.AuditableController()
    assert app.detector is None


def test_model_default_prefers_completed_retraining_and_honors_override(tmp_path,monkeypatch):
    from controller.auditable_controller import select_model_directory
    monkeypatch.delenv('PAML_MODEL_DIR',raising=False)
    assert select_model_directory(tmp_path)==tmp_path/'models'
    (tmp_path/'models_live').mkdir()
    (tmp_path/'models_live/training_report.json').write_text('{}')
    assert select_model_directory(tmp_path)==tmp_path/'models_live'
    monkeypatch.setenv('PAML_MODEL_DIR',str(tmp_path/'explicit'))
    assert select_model_directory(tmp_path)==tmp_path/'explicit'
