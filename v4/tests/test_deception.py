from src.deception import DeceptionManager


def test_deception_ignores_non_attack():
    d = DeceptionManager(1.0)
    result = d.inspect("SUSPICIOUS", "HTTP_Flood", "s", 1)
    assert not result.routed_to_decoy
    assert d.decoy_hits == 0


def test_deception_can_capture_confirmed_attack():
    d = DeceptionManager(1.0)
    result = d.inspect("ATTACK", "HTTP_Flood", "s", 1)
    assert result.routed_to_decoy
    assert result.decoy == "decoy-web"
    assert d.decoy_hits == 1
