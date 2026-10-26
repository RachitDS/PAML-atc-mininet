"""Deterministic deception/honeypot routing for Phase 4."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class DeceptionDecision:
    routed_to_decoy: bool
    decoy: str | None
    reason: str


class DeceptionManager:
    """Route a controlled fraction of confirmed attacks to decoy services."""

    DECOYS = {
        "ICMP_Flood": "decoy-icmp",
        "SYN_Flood": "decoy-tcp",
        "UDP_Flood": "decoy-udp",
        "HTTP_Flood": "decoy-web",
        "Slowloris": "decoy-web-slow",
    }

    def __init__(self, capture_probability: float = 0.25, salt: str = "phase4") -> None:
        if not 0.0 <= capture_probability <= 1.0:
            raise ValueError("capture_probability must be between 0 and 1")
        self.capture_probability = float(capture_probability)
        self.salt = str(salt)
        self.decoy_hits = 0
        self.attack_decisions = 0
        self.events: list[dict] = []

    def reset(self) -> None:
        self.decoy_hits = 0
        self.attack_decisions = 0
        self.events.clear()

    def _score(self, source_id: str, flow_index: int) -> float:
        digest = hashlib.sha256(f"{self.salt}|{source_id}|{flow_index}".encode()).hexdigest()
        return int(digest[:12], 16) / float(16**12)

    def inspect(self, state: str, attack_type: str, source_id: str, flow_index: int) -> DeceptionDecision:
        if state != "ATTACK":
            return DeceptionDecision(False, None, "Deception only engages after confirmed attack state")

        self.attack_decisions += 1
        decoy = self.DECOYS.get(attack_type, "decoy-generic")
        routed = self._score(source_id, int(flow_index)) < self.capture_probability
        if routed:
            self.decoy_hits += 1
            self.events.append({"flow_index": int(flow_index), "attack_type": attack_type, "decoy": decoy})
            return DeceptionDecision(True, decoy, "Confirmed attack sampled for deception")
        return DeceptionDecision(False, None, "Attack retained on protected path")

    def metrics(self) -> dict:
        rate = self.decoy_hits / self.attack_decisions if self.attack_decisions else 0.0
        return {
            "decoy_hits": self.decoy_hits,
            "attack_decisions": self.attack_decisions,
            "decoy_capture_rate": round(rate, 4),
        }
