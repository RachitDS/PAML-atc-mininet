from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phase6b_experiment import CONFIGS, run_seed


def test_phase6b_has_four_configurations():
    rows = run_seed(0)
    assert {r["configuration"] for r in rows} == set(CONFIGS)


def test_phase6b_baseline_is_not_zero_detection():
    rows = run_seed(0)
    baseline = next(r for r in rows if r["configuration"] == "A1_StaticThreshold")
    assert baseline["f1"] > 0.0


def test_phase6b_operational_metrics_exist():
    rows = run_seed(0)
    for row in rows:
        assert 0.0 <= row["benign_pdr"] <= 1.0
        assert 0.0 <= row["attack_pdr"] <= 1.0
        assert 0.0 <= row["attack_block_rate"] <= 1.0
        assert row["rtt_ms"] > 0.0
