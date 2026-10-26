"""Phase-5 SDN/OpenFlow-style control-plane simulation.

This module models the control path required by the research architecture:

    packet -> switch -> PACKET_IN -> controller -> PAML/ATC/MTD/deception
           -> FLOW_MOD -> switch flow table

It is intentionally a deterministic simulator, not a replacement for a real
OpenFlow stack. Mininet/Ryu integration is reserved for a later phase.

REUSED: Phase-4 defense orchestrator.
NEW: packet-in/flow-mod messages, switch flow table, controller pipeline, and
     control-plane latency measurements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter_ns
from typing import Dict, List, Optional

from src.defense_orchestrator import DefenseDecision, DefenseOrchestrator


@dataclass(frozen=True)
class PacketIn:
    """A switch-to-controller packet-in event."""

    packet_id: int
    source_id: str
    protocol: str
    destination_port: int
    payload_bytes: int = 512
    reason: str = "TABLE_MISS"


@dataclass(frozen=True)
class FlowMatch:
    """Minimal match key for the simulated flow table."""

    source_id: str
    protocol: str
    destination_port: int


@dataclass(frozen=True)
class FlowMod:
    """Controller-to-switch rule installation/modification message."""

    command: str
    match: FlowMatch
    action: str
    target: str
    rate_limit_pps: int
    drop_probability: float
    priority: int
    idle_timeout: int
    reason: str


@dataclass
class FlowEntry:
    """Installed flow-table entry."""

    flow_mod: FlowMod
    packet_count: int = 0
    byte_count: int = 0


class SimulatedSwitch:
    """Small deterministic switch model with an OpenFlow-like flow table."""

    def __init__(self, name: str = "s1") -> None:
        self.name = name
        self.flow_table: Dict[FlowMatch, FlowEntry] = {}
        self.flow_mod_history: List[FlowMod] = []

    def apply_flow_mod(self, flow_mod: FlowMod) -> None:
        if flow_mod.command not in {"ADD", "MODIFY", "DELETE"}:
            raise ValueError(f"Unsupported FLOW_MOD command: {flow_mod.command}")
        self.flow_mod_history.append(flow_mod)
        if flow_mod.command == "DELETE":
            self.flow_table.pop(flow_mod.match, None)
        else:
            self.flow_table[flow_mod.match] = FlowEntry(flow_mod)

    def lookup(self, match: FlowMatch) -> Optional[FlowEntry]:
        return self.flow_table.get(match)

    def flow_count(self) -> int:
        return len(self.flow_table)


@dataclass(frozen=True)
class SDNDecision:
    """Complete controller result for one packet-in."""

    packet_in: PacketIn
    paml_decision: object
    defense: DefenseDecision
    flow_mod: FlowMod
    controller_latency_ms: float
    decision_latency_ms: float
    flow_mod_latency_ms: float


class SDNController:
    """Connect packet-in events to the Phase-4 defense pipeline.

    The controller deliberately keeps PAML state per source. This prevents a
    benign source and an attack source from contaminating each other's temporal
    windows, while allowing repeated packet-ins from one source to accumulate
    persistence evidence.
    """

    PROTOCOL_PORTS = {"ICMP": 0, "TCP": 80, "UDP": 53}

    def __init__(
        self,
        detector,
        defense: DefenseOrchestrator | None = None,
        switch: SimulatedSwitch | None = None,
        sample_every: int = 1,
        idle_timeout: int = 30,
    ) -> None:
        if sample_every < 1:
            raise ValueError("sample_every must be at least 1")
        if idle_timeout < 1:
            raise ValueError("idle_timeout must be at least 1")
        self.detector = detector
        self.defense = defense or DefenseOrchestrator()
        self.switch = switch or SimulatedSwitch()
        self.sample_every = int(sample_every)
        self.idle_timeout = int(idle_timeout)
        self.packet_in_count = 0
        self.flow_mod_count = 0
        self.latencies_ms: List[float] = []
        self.decision_latencies_ms: List[float] = []
        self.flow_mod_latencies_ms: List[float] = []

    def reset(self) -> None:
        self.detector.reset()
        self.defense.reset()
        self.packet_in_count = 0
        self.flow_mod_count = 0
        self.latencies_ms.clear()
        self.decision_latencies_ms.clear()
        self.flow_mod_latencies_ms.clear()
        self.switch.flow_table.clear()
        self.switch.flow_mod_history.clear()

    @staticmethod
    def _target_for(defense: DefenseDecision) -> str:
        if defense.deception.routed_to_decoy and defense.deception.decoy:
            return defense.deception.decoy
        return defense.active_target

    def _build_flow_mod(self, packet: PacketIn, defense: DefenseDecision) -> FlowMod:
        action = defense.atc.mode
        if defense.deception.routed_to_decoy:
            action = "REDIRECT_DECOY"
        elif defense.atc.mode == "ALLOW":
            action = "OUTPUT"
        elif defense.atc.mode == "RATE_LIMIT":
            action = "METER_OUTPUT"
        elif defense.atc.mode == "MITIGATE":
            action = "DROP_OR_SAMPLE"

        priority = {"ALLOW": 10, "RATE_LIMIT": 50, "MITIGATE": 100}.get(defense.atc.mode, 10)
        return FlowMod(
            command="MODIFY" if self.switch.lookup(FlowMatch(packet.source_id, packet.protocol, packet.destination_port)) else "ADD",
            match=FlowMatch(packet.source_id, packet.protocol, packet.destination_port),
            action=action,
            target=self._target_for(defense),
            rate_limit_pps=defense.atc.rate_limit_pps,
            drop_probability=defense.atc.drop_probability,
            priority=priority,
            idle_timeout=self.idle_timeout,
            reason=defense.atc.reason,
        )

    def process_packet_in(self, packet: PacketIn, flow_record: dict) -> SDNDecision:
        """Process one packet-in and immediately install its FLOW_MOD rule."""
        start = perf_counter_ns()
        self.packet_in_count += 1

        decision_start = perf_counter_ns()
        paml_decision = self.detector.predict_flow(flow_record)
        defense = self.defense.decide(
            paml_decision,
            source_id=packet.source_id,
            flow_index=packet.packet_id,
        )
        decision_ms = (perf_counter_ns() - decision_start) / 1_000_000.0

        flow_mod = self._build_flow_mod(packet, defense)
        mod_start = perf_counter_ns()
        self.switch.apply_flow_mod(flow_mod)
        mod_ms = (perf_counter_ns() - mod_start) / 1_000_000.0

        total_ms = (perf_counter_ns() - start) / 1_000_000.0
        self.flow_mod_count += 1
        self.latencies_ms.append(total_ms)
        self.decision_latencies_ms.append(decision_ms)
        self.flow_mod_latencies_ms.append(mod_ms)

        return SDNDecision(packet, paml_decision, defense, flow_mod, total_ms, decision_ms, mod_ms)

    def metrics(self) -> dict:
        def summary(values: List[float]) -> dict:
            if not values:
                return {"count": 0, "mean_ms": 0.0, "p95_ms": 0.0}
            ordered = sorted(values)
            # Nearest-rank style percentile keeps the implementation dependency-free.
            index = max(0, min(len(ordered) - 1, int((0.95 * len(ordered)) + 0.999999) - 1))
            return {
                "count": len(values),
                "mean_ms": round(sum(values) / len(values), 4),
                "p95_ms": round(ordered[index], 4),
            }

        return {
            "switch": self.switch.name,
            "packet_in_count": self.packet_in_count,
            "flow_mod_count": self.flow_mod_count,
            "flow_table_entries": self.switch.flow_count(),
            "packet_in_to_flow_mod_ms": summary(self.latencies_ms),
            "controller_decision_ms": summary(self.decision_latencies_ms),
            "flow_mod_apply_ms": summary(self.flow_mod_latencies_ms),
        }
