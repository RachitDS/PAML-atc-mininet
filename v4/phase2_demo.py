"""Phase 2 PAML online-detection demonstration.

Runs the trained Phase-1B models on a held-out ordered sequence and prints
state transitions. This is a detector demonstration, not an SDN testbed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import MODEL_DIR, RANDOM_SEED, SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE
from config_phase2 import PAML_ATTACK_THRESHOLD, PAML_PERSISTENCE, PAML_WINDOW_SIZE
from src.dataset import generate_dataset
from src.paml_detector import PAMLDetector


def main() -> None:
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, RANDOM_SEED + 7)
    # Pick a deterministic attack sequence. No labels are supplied to the
    # detector; labels are used only after inference to inspect the demo.
    attack_sequence = df[df["attack_type"] == "HTTP_Flood"]["sequence_id"].iloc[0]
    stream = df[df["sequence_id"] == attack_sequence].sort_values("flow_index")

    detector = PAMLDetector(MODEL_DIR, window_size=PAML_WINDOW_SIZE, attack_threshold=PAML_ATTACK_THRESHOLD, persistence=PAML_PERSISTENCE)
    decisions = detector.predict_dataframe(stream)
    decisions["true_type"] = stream["attack_type"].to_numpy()
    decisions["flow_index"] = stream["flow_index"].to_numpy()

    print("=== PAML-ATC V2 Phase-2 Online Detection Demo ===")
    print(f"Stream class (inspection only): HTTP_Flood")
    print(f"Flows: {len(stream)} | window: {PAML_WINDOW_SIZE} | threshold: {PAML_ATTACK_THRESHOLD:.2f} | persistence: {PAML_PERSISTENCE}")
    print("\nflow  state       p_attack  predicted_type  consecutive")
    print("----  ----------  --------  ---------------  -----------")
    for _, row in decisions.iterrows():
        print(
            f"{int(row['flow_index']):>4}  {str(row['state']):<10}  "
            f"{row['attack_probability']:.3f}     {str(row['attack_type']):<15}  "
            f"{int(row['consecutive_positive']):>11}"
        )

    print("\nOperational interpretation:")
    print("BENIGN -> no immediate mitigation")
    print("SUSPICIOUS -> continue observation / accumulate evidence")
    print("ATTACK -> hand decision to the Adaptive ATC layer")


if __name__ == "__main__":
    main()
