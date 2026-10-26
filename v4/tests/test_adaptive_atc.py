from types import SimpleNamespace
from src.adaptive_atc import AdaptiveATC


def d(state, p=0.9, attack_type="HTTP_Flood", cp=0.9):
    return SimpleNamespace(
        state=state,
        attack_probability=p,
        attack_type=attack_type,
        attack_type_probability=cp,
    )


def test_benign_allows_capacity():
    action = AdaptiveATC(1000).decide(d("BENIGN"))
    assert action.mode == "ALLOW"
    assert action.rate_limit_pps == 1000
    assert action.drop_probability == 0.0


def test_suspicious_rate_limits_without_full_mitigation():
    action = AdaptiveATC(1000).decide(d("SUSPICIOUS"))
    assert action.mode == "RATE_LIMIT"
    assert action.rate_limit_pps == 750
    assert action.drop_probability < 0.4


def test_attack_uses_attack_type_policy():
    action = AdaptiveATC(1000).decide(d("ATTACK", attack_type="Slowloris"))
    assert action.mode == "MITIGATE"
    assert action.rate_limit_pps < 100
    assert 0.4 <= action.drop_probability <= 0.95
