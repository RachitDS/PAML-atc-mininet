from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phase6b1_experiment import CONFIGS, run_seed


def test_phase6b1_has_four_configurations():
    rows = run_seed(0)
    assert {r["configuration"] for r in rows} == set(CONFIGS)


def test_phase6b1_a4_has_mtd_activity():
    rows = run_seed(0)
    a4 = next(r for r in rows if r["configuration"] == "A4_FULL")
    assert a4["mtd_rotations"] > 0
    assert a4["mtd_unique_target_count"] >= 2
    assert 0.0 < a4["mtd_target_coverage"] <= 1.0


def test_phase6b1_a4_has_deception_measurement():
    rows = run_seed(0)
    a4 = next(r for r in rows if r["configuration"] == "A4_FULL")
    assert a4["deception_attack_decisions"] > 0
    assert a4["decoy_hits"] >= 0
    assert 0.0 <= a4["deception_capture_rate"] <= 1.0
    assert 0.0 <= a4["attack_redirect_rate"] <= 1.0
    assert a4["diverted_attack_pps"] >= 0.0


def test_phase6b1_non_a4_does_not_claim_mtd_or_deception():
    rows = run_seed(0)
    for row in rows:
        if row["configuration"] != "A4_FULL":
            assert row["mtd_rotations"] == 0
            assert row["decoy_hits"] == 0
            assert row["attack_redirect_rate"] == 0.0
