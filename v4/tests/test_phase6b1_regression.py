from pathlib import Path


def test_phase6b1_results_directory_exists():
    root = Path(__file__).resolve().parents[1]
    assert (root / "results" / "processed").exists()


def test_phase6b1_experiment_is_present():
    root = Path(__file__).resolve().parents[1]
    assert (root / "phase6b1_experiment.py").exists()
