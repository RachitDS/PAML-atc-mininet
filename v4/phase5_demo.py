"""Phase 5: SDN packet-in -> PAML -> ATC -> MTD/deception -> flow-mod demo."""
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
from src.sdn_simulator import PacketIn, SDNController, SimulatedSwitch


def main() -> None:
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, RANDOM_SEED + 17)
    benign_seq = df[df["attack_type"] == "Benign"]["sequence_id"].iloc[0]
    attack_seq = df[df["attack_type"] == "HTTP_Flood"]["sequence_id"].iloc[0]
    benign = df[df["sequence_id"] == benign_seq].sort_values("flow_index").head(8)
    attack = df[df["sequence_id"] == attack_seq].sort_values("flow_index").head(16)

    detector = PAMLDetector(MODEL_DIR, PAML_WINDOW_SIZE, PAML_ATTACK_THRESHOLD, PAML_PERSISTENCE)
    defense = DefenseOrchestrator(capacity_pps=1000, rotation_interval=5, deception_probability=0.25)
    switch = SimulatedSwitch("s1")
    controller = SDNController(detector, defense, switch, sample_every=1, idle_timeout=30)

    print("=== PAML-ATC V2 Phase-5 SDN Control-Plane Demo ===")
    print("Path: PACKET_IN -> PAML -> Adaptive ATC -> MTD/Deception -> FLOW_MOD")
    print("Switch: s1 | sources: benign-host, attacker-host")
    print("\npacket source         PAML_state   p_attack  PAML_type       ATC_mode    action           target       latency_ms")
    print("------ ---------------- ----------- -------- -------------- ----------- ---------------- ------------ ----------")

    packet_id = 0
    for source, stream, protocol, port in [
        ("benign-host", benign, "TCP", 80),
        ("attacker-host", attack, "TCP", 80),
    ]:
        controller.detector.reset()
        for record in stream.to_dict(orient="records"):
            packet = PacketIn(packet_id, source, protocol, port)
            result = controller.process_packet_in(packet, record)
            print(
                f"{packet_id:>6} {source:<16} {result.paml_decision.state:<11} "
                f"{result.paml_decision.attack_probability:>8.3f} "
                f"{result.paml_decision.attack_type:<14} {result.defense.atc.mode:<11} "
                f"{result.flow_mod.action:<16} {result.flow_mod.target:<12} "
                f"{result.controller_latency_ms:>10.3f}"
            )
            packet_id += 1

    print("\nPhase-5 SDN metrics:")
    print(controller.metrics())
    print("\nInstalled flow rules:")
    for match, entry in switch.flow_table.items():
        print(
            f"{match.source_id:16} {match.protocol:5} dport={match.destination_port:<3} "
            f"action={entry.flow_mod.action:<15} target={entry.flow_mod.target:<14} "
            f"limit={entry.flow_mod.rate_limit_pps:<4} priority={entry.flow_mod.priority}"
        )

    print("\nOperational SDN chain:")
    print("Switch table miss -> PACKET_IN")
    print("Controller -> PAML online temporal inference")
    print("PAML -> Adaptive ATC policy")
    print("ATC -> MTD/deception decision")
    print("Controller -> FLOW_MOD")
    print("Switch -> install/update flow entry")
    print("Scope: simulated OpenFlow-style control plane; Mininet/Ryu integration comes later.")


if __name__ == "__main__":
    main()
