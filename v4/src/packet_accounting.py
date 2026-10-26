"""Deterministic packet accounting for Phase-6B.3.

The experiment previously reported PDR-like values from rate/pps aggregates but
had no packet denominators.  This module creates explicit integer packet
counters from each flow's offered packet rate and flow duration, then applies
an explicit policy admission and network-capacity factor.

IMPORTANT: this is still a synthetic service-capacity model, not a packet
capture or live Mininet measurement.  The counters are therefore *simulated
packet accounting*, but the PDR arithmetic itself uses real offered/delivered
packet counts and never reconstructs a denominator from PDR values.
"""
from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class PacketOutcome:
    offered_packets: int
    policy_admitted_packets: int
    delivered_packets: int
    diverted_packets: int = 0
    dropped_packets: int = 0


class PacketAccounting:
    """Convert one flow into explicit packet offered/delivered counters."""

    # Dataset flow_duration is expressed in microseconds.
    DURATION_SCALE = 1_000_000.0

    def __init__(self, capacity_pps: float):
        if capacity_pps <= 0:
            raise ValueError("capacity_pps must be positive")
        self.capacity_pps = float(capacity_pps)
        self.reset()

    def reset(self) -> None:
        self.benign_offered_packets = 0
        self.benign_delivered_packets = 0
        self.attack_offered_packets = 0
        self.attack_delivered_packets = 0
        self.attack_diverted_packets = 0
        self.decoy_delivered_packets = 0
        self.total_policy_admitted_packets = 0
        self.total_dropped_packets = 0

    @classmethod
    def offered_packets(cls, pps: float, flow_duration_us: float) -> int:
        if pps < 0 or flow_duration_us < 0:
            raise ValueError("pps and flow duration must be non-negative")
        # At least one packet for a non-empty observed flow.
        raw = float(pps) * float(flow_duration_us) / cls.DURATION_SCALE
        return max(1, int(round(raw)))

    @staticmethod
    def policy_admission(offered: int, rate_limit_pps: int, drop_probability: float,
                         flow_duration_us: float) -> int:
        if offered < 0:
            raise ValueError("offered must be non-negative")
        if rate_limit_pps < 0:
            raise ValueError("rate_limit_pps must be non-negative")
        if not 0.0 <= drop_probability <= 1.0:
            raise ValueError("drop_probability must be in [0,1]")
        duration_s = max(float(flow_duration_us) / PacketAccounting.DURATION_SCALE, 0.0)
        rate_cap = int(math.floor(float(rate_limit_pps) * duration_s))
        admitted_before_drop = min(offered, rate_cap) if rate_limit_pps < 10**12 else offered
        admitted = int(math.floor(admitted_before_drop * (1.0 - float(drop_probability))))
        return max(0, min(offered, admitted))

    def record_flow(
        self,
        *,
        label: int,
        offered_pps: float,
        flow_duration_us: float,
        rate_limit_pps: int,
        drop_probability: float,
        capacity_factor: float,
        diverted_fraction: float = 0.0,
    ) -> PacketOutcome:
        """Account packets for one flow.

        ``capacity_factor`` is an explicit network-service capacity term in
        [0,1].  ``diverted_fraction`` is used only for confirmed attacks routed
        to a decoy; diverted packets are excluded from attack delivery to the
        intended PLC but counted separately as decoy delivery.
        """
        if not 0.0 <= capacity_factor <= 1.0:
            raise ValueError("capacity_factor must be in [0,1]")
        if not 0.0 <= diverted_fraction <= 1.0:
            raise ValueError("diverted_fraction must be in [0,1]")

        offered = self.offered_packets(offered_pps, flow_duration_us)
        admitted = self.policy_admission(
            offered, rate_limit_pps, drop_probability, flow_duration_us
        )
        # Deterministic integer delivery; no Bernoulli noise is injected into
        # packet counts, so repeated runs are auditable.
        capacity_delivered = int(math.floor(admitted * float(capacity_factor)))
        capacity_delivered = max(0, min(admitted, capacity_delivered))

        diverted = 0
        delivered = capacity_delivered
        if label == 1 and diverted_fraction > 0.0:
            diverted = int(math.floor(capacity_delivered * diverted_fraction))
            diverted = max(0, min(capacity_delivered, diverted))
            delivered = capacity_delivered - diverted

        dropped = offered - capacity_delivered
        self.total_policy_admitted_packets += admitted
        self.total_dropped_packets += dropped
        if label == 0:
            self.benign_offered_packets += offered
            self.benign_delivered_packets += delivered
        else:
            self.attack_offered_packets += offered
            self.attack_delivered_packets += delivered
            self.attack_diverted_packets += diverted
            self.decoy_delivered_packets += diverted

        return PacketOutcome(offered, admitted, delivered, diverted, dropped)

    def counters(self) -> dict:
        total_offered = self.benign_offered_packets + self.attack_offered_packets
        total_delivered = self.benign_delivered_packets + self.attack_delivered_packets
        return {
            "benign_offered_packets": int(self.benign_offered_packets),
            "benign_delivered_packets": int(self.benign_delivered_packets),
            "attack_offered_packets": int(self.attack_offered_packets),
            "attack_delivered_packets": int(self.attack_delivered_packets),
            "attack_diverted_packets": int(self.attack_diverted_packets),
            "decoy_delivered_packets": int(self.decoy_delivered_packets),
            "total_offered_packets": int(total_offered),
            "total_delivered_packets": int(total_delivered),
            "total_policy_admitted_packets": int(self.total_policy_admitted_packets),
            "total_dropped_packets": int(self.total_dropped_packets),
        }


def pdr(delivered: int, offered: int) -> float:
    """Packet delivery ratio from explicit packet counters only."""
    if offered <= 0:
        raise ValueError("offered packet count must be positive")
    return float(delivered) / float(offered)
