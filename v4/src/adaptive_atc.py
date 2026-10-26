"""Adaptive Traffic Control policy engine for Phase 3.

This module is a simulation/control-policy layer, not a real SDN controller.
It consumes a PAMLDecision and maps it to a deterministic mitigation action.

REUSED: PAML operational states and attack classes.
MODIFIED: detection output is now connected to a mitigation policy.
NEW: adaptive, attack-type-aware ATC actions with per-source state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class ATCAction:
    mode: str
    rate_limit_pps: int
    priority: str
    drop_probability: float
    reason: str


class AdaptiveATC:
    """Map PAML decisions to simulated adaptive traffic-control actions."""

    DEFAULT_LIMITS = {
        "ICMP_Flood": 120,
        "SYN_Flood": 160,
        "UDP_Flood": 100,
        "HTTP_Flood": 180,
        "Slowloris": 80,
    }

    def __init__(self, capacity_pps: int = 1000) -> None:
        if capacity_pps <= 0:
            raise ValueError("capacity_pps must be positive")
        self.capacity_pps = int(capacity_pps)
        self.source_state: Dict[str, str] = {}

    def reset(self) -> None:
        self.source_state.clear()

    def decide(self, decision, source_id: str = "default") -> ATCAction:
        """Return the action for one PAML decision.

        The action is intentionally deterministic so that later experiments can
        compare policies under identical seeds and traffic traces.
        """
        if decision.state == "BENIGN":
            self.source_state[source_id] = "ALLOW"
            return ATCAction(
                mode="ALLOW",
                rate_limit_pps=self.capacity_pps,
                priority="NORMAL",
                drop_probability=0.0,
                reason="PAML classified traffic as benign",
            )

        if decision.state == "SUSPICIOUS":
            self.source_state[source_id] = "RATE_LIMIT"
            return ATCAction(
                mode="RATE_LIMIT",
                rate_limit_pps=max(1, int(self.capacity_pps * 0.75)),
                priority="LOW",
                drop_probability=0.10,
                reason="Accumulate evidence before strong mitigation",
            )

        attack_type = decision.attack_type
        base_limit = self.DEFAULT_LIMITS.get(attack_type, 100)
        confidence = max(0.0, min(1.0, float(decision.attack_probability)))
        class_confidence = max(0.0, min(1.0, float(decision.attack_type_probability)))

        # Stronger evidence and stronger class confidence reduce the permitted
        # attack rate. The floor prevents a zero-rate rule in this simulator.
        strength = 0.5 * confidence + 0.5 * class_confidence
        adaptive_limit = max(10, int(base_limit * (1.0 - 0.35 * strength)))
        drop_probability = min(0.95, max(0.40, 0.40 + 0.55 * strength))

        self.source_state[source_id] = "MITIGATE"
        return ATCAction(
            mode="MITIGATE",
            rate_limit_pps=adaptive_limit,
            priority="PROTECTED",
            drop_probability=round(drop_probability, 4),
            reason=f"Persistent {attack_type} detected by PAML",
        )
