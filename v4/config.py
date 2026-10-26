from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
MODEL_DIR = ROOT / "models"
RESULT_DIR = ROOT / "results"
PLOT_DIR = ROOT / "plots"

RANDOM_SEED = 42
WINDOW_SIZE = 5

# Phase 1B: keep the same sequence scale as Phase 1 so results are comparable.
SEQUENCES_PER_CLASS = 120
FLOWS_PER_SEQUENCE = 40
TEST_SIZE = 0.20

# Hard cases are generated inside src.dataset. They include benign bursts and
# weaker/evasive attack sequences to make binary detection non-trivial.
MODEL_PATH = MODEL_DIR / "paml_binary_rf_phase1b.joblib"
SCALER_PATH = MODEL_DIR / "paml_scaler_phase1b.joblib"
FEATURES_PATH = MODEL_DIR / "paml_features_phase1b.txt"
TRAINING_METRICS_PATH = RESULT_DIR / "processed" / "training_metrics_phase1b.json"
DATASET_PATH = PROCESSED_DIR / "paml_temporal_dataset_phase1b.csv"
