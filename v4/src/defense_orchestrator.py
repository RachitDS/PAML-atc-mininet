"""Phase-4 orchestration: PAML -> ATC -> MTD/deception."""
from __future__ import annotations

from dataclasses import dataclass
from src.adaptive_atc import AdaptiveATC, ATCAction
from src.deception import DeceptionDecision, DeceptionManager
from src.mtd import MTDManager, MTDEvent


@dataclass(frozen=True)
class DefenseDecision:
    atc: ATCAction
    mtd_event: MTDEvent | None
    deception: DeceptionDecision
    active_target: str


class DefenseOrchestrator:
    """Combine Phase-3 ATC with Phase-4 MTD and deception state."""

    def __init__(self, capacity_pps: int = 1000, rotation_interval: int = 5,
                 deception_probability: float = 0.25) -> None:
        self.atc = AdaptiveATC(capacity_pps=capacity_pps)
        self.mtd = MTDManager(rotation_interval=rotation_interval)
        self.deception = DeceptionManager(capture_probability=deception_probability)
        self.previous_state: dict[str, str] = {}

    def reset(self) -> None:
        self.atc.reset()
        self.mtd.reset()
        self.deception.reset()
        self.previous_state.clear()

    def decide(self, paml_decision, source_id: str = "default", flow_index: int = 0) -> DefenseDecision:
        action = self.atc.decide(paml_decision, source_id=source_id)
        previous = self.previous_state.get(source_id)
        entering_attack = paml_decision.state == "ATTACK" and previous != "ATTACK"

        mtd_event = None
        if paml_decision.state == "ATTACK":
            mtd_event = self.mtd.on_attack(paml_decision.attack_type, force=entering_attack)

        deception = self.deception.inspect(
            paml_decision.state, paml_decision.attack_type, source_id, flow_index
        )
        self.previous_state[source_id] = paml_decision.state
        return DefenseDecision(action, mtd_event, deception, self.mtd.current_target)

    def metrics(self) -> dict:
        return {
            "mtd": self.mtd.metrics(),
            "deception": self.deception.metrics(),
        }
