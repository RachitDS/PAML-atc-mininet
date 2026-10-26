from types import SimpleNamespace
from src.defense_orchestrator import DefenseOrchestrator


def decision(state, attack_type="HTTP_Flood", p=0.99):
    return SimpleNamespace(
        state=state,
        attack_probability=p,
        attack_type=attack_type,
        attack_type_probability=0.99,
    )


def test_orchestrator_enters_mtd_on_confirmed_attack():
    d = DefenseOrchestrator(deception_probability=1.0)
    r = d.decide(decision("SUSPICIOUS"), "s", 0)
    assert r.atc.mode == "RATE_LIMIT"
    r = d.decide(decision("ATTACK"), "s", 1)
    assert r.atc.mode == "MITIGATE"
    assert r.mtd_event is not None
    assert r.active_target == "PLC-B"
    assert r.deception.routed_to_decoy
