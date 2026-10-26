"""Phase 4: PAML -> Adaptive ATC -> MTD + deception demonstration."""
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
from src.defense_orchestrator import DefenseOrchestrator


def main() -> None:
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, RANDOM_SEED + 11)
    attack_sequence = df[df["attack_type"] == "HTTP_Flood"]["sequence_id"].iloc[0]
    stream = df[df["sequence_id"] == attack_sequence].sort_values("flow_index")

    detector = PAMLDetector(MODEL_DIR, PAML_WINDOW_SIZE, PAML_ATTACK_THRESHOLD, PAML_PERSISTENCE)
    defense = DefenseOrchestrator(capacity_pps=1000, rotation_interval=5, deception_probability=0.25)

    print("=== PAML-ATC V2 Phase-4 MTD + Deception Demo ===")
    print(f"Stream: HTTP_Flood | flows: {len(stream)}")
    print("MTD targets: PLC-A -> PLC-B -> PLC-C | interval: 5 attack events")
    print("Deception capture probability: 0.25")
    print("\nflow state       p_attack PAML_type       ATC_mode   target  MTD_event       decoy")
    print("---- ----------- -------- --------------  ---------  ------  --------------  --------------")

    for record in stream.to_dict(orient="records"):
        idx = int(record["flow_index"])
        decision = detector.predict_flow(record)
        result = defense.decide(decision, source_id="demo-source", flow_index=idx)
        mtd = result.mtd_event.event if result.mtd_event else "-"
        decoy = result.deception.decoy or "-"
        print(
            f"{idx:>4} {decision.state:<11} {decision.attack_probability:>8.3f} "
            f"{decision.attack_type:<14} {result.atc.mode:<9} {result.active_target:<7} "
            f"{mtd:<14} {decoy:<14}"
        )

    print("\nPhase-4 metrics:")
    print(defense.metrics())
    print("\nOperational chain:")
    print("PAML BENIGN     -> ALLOW")
    print("PAML SUSPICIOUS -> RATE_LIMIT / observe")
    print("PAML ATTACK     -> adaptive MITIGATE -> MTD rotation + selective deception")
    print("Scope: simulated target/deception control; real SDN/OpenFlow comes later.")


if __name__ == "__main__":
    main()
