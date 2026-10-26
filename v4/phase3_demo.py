"""Phase 3: PAML -> Adaptive ATC integration demonstration."""
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
from src.adaptive_atc import AdaptiveATC


def main() -> None:
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, RANDOM_SEED + 7)
    attack_sequence = df[df["attack_type"] == "HTTP_Flood"]["sequence_id"].iloc[0]
    stream = df[df["sequence_id"] == attack_sequence].sort_values("flow_index")

    detector = PAMLDetector(
        MODEL_DIR,
        window_size=PAML_WINDOW_SIZE,
        attack_threshold=PAML_ATTACK_THRESHOLD,
        persistence=PAML_PERSISTENCE,
    )
    atc = AdaptiveATC(capacity_pps=1000)

    print("=== PAML-ATC V2 Phase-3 PAML -> Adaptive ATC Demo ===")
    print(f"Stream: HTTP_Flood | flows: {len(stream)}")
    print("\nflow state       p_attack  PAML_type       ATC_mode    limit_pps drop_p")
    print("---- ----------- --------  --------------  ----------  --------- ------")

    for record in stream.to_dict(orient="records"):
        flow_index = int(record["flow_index"])
        decision = detector.predict_flow(record)
        action = atc.decide(decision, source_id="demo-source")
        print(
            f"{flow_index:>4} {decision.state:<11} {decision.attack_probability:>8.3f}  "
            f"{decision.attack_type:<14}  {action.mode:<10}  "
            f"{action.rate_limit_pps:>9} {action.drop_probability:>6.2f}"
        )

    print("\nOperational chain:")
    print("PAML BENIGN    -> ALLOW")
    print("PAML SUSPICIOUS-> RATE_LIMIT / observe")
    print("PAML ATTACK    -> adaptive attack-type-aware MITIGATE")
    print("Note: ATC actions are simulated policies; real SDN flow-mod installation comes later.")


if __name__ == "__main__":
    main()
