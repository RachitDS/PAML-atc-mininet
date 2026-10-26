from pathlib import Path

from src.sdn_simulator import FlowMatch, FlowMod, PacketIn, SDNController, SimulatedSwitch


class FakeDetector:
    def __init__(self, decisions):
        self.decisions = iter(decisions)

    def reset(self):
        pass

    def predict_flow(self, flow):
        return next(self.decisions)


def fake_decision(state="BENIGN", attack_type="HTTP_Flood", p=0.1):
    from src.paml_detector import PAMLDecision
    return PAMLDecision(
        is_attack=state == "ATTACK",
        state=state,
        attack_probability=p,
        attack_type=attack_type,
        attack_type_probability=0.9,
        consecutive_positive=3 if state == "ATTACK" else 0,
        window_size=5,
    )


def test_switch_flow_mod_add_and_lookup():
    sw = SimulatedSwitch()
    match = FlowMatch("h1", "TCP", 80)
    mod = FlowMod("ADD", match, "OUTPUT", "PLC-A", 1000, 0.0, 10, 30, "test")
    sw.apply_flow_mod(mod)
    assert sw.lookup(match).flow_mod.action == "OUTPUT"
    assert sw.flow_count() == 1


def test_controller_installs_flow_mod_for_benign():
    detector = FakeDetector([fake_decision("BENIGN")])
    controller = SDNController(detector)
    packet = PacketIn(0, "h1", "TCP", 80)
    result = controller.process_packet_in(packet, {})
    assert result.flow_mod.action == "OUTPUT"
    assert result.flow_mod.target == "PLC-A"
    assert controller.metrics()["flow_mod_count"] == 1


def test_controller_maps_suspicious_to_rate_limit():
    detector = FakeDetector([fake_decision("SUSPICIOUS", p=0.8)])
    controller = SDNController(detector)
    result = controller.process_packet_in(PacketIn(1, "h2", "TCP", 80), {})
    assert result.flow_mod.action == "METER_OUTPUT"
    assert result.flow_mod.rate_limit_pps < 1000


def test_controller_maps_attack_to_mitigation():
    detector = FakeDetector([fake_decision("ATTACK", p=0.99)])
    controller = SDNController(detector)
    result = controller.process_packet_in(PacketIn(2, "h3", "TCP", 80), {})
    assert result.flow_mod.action in {"DROP_OR_SAMPLE", "REDIRECT_DECOY"}
    assert result.flow_mod.priority == 100


def test_latency_metrics_have_mean_and_p95():
    detector = FakeDetector([fake_decision("BENIGN")])
    controller = SDNController(detector)
    controller.process_packet_in(PacketIn(3, "h4", "TCP", 80), {})
    metrics = controller.metrics()
    summary = metrics["packet_in_to_flow_mod_ms"]
    assert summary["count"] == 1
    assert summary["mean_ms"] >= 0.0
    assert summary["p95_ms"] >= 0.0
