"""Online flow feature extraction for the real OpenFlow path.

A Ryu PACKET_IN stream is aggregated into short flow records.  The resulting
17 base features match the Phase-1B model schema.  The five-flow temporal
window is handled by ``PAMLDetector`` after the flow record is finalized.

This is a testbed adapter: it does not claim that OpenFlow packet-in fields are
identical to CIC-DDoS2019 flow-export fields.
"""
from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Dict, Tuple


@dataclass
class FlowStats:
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes_total: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_iat_sum: float = 0.0
    bwd_iat_sum: float = 0.0
    fwd_last_ts: float = 0.0
    bwd_last_ts: float = 0.0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    lengths_sum: float = 0.0
    lengths_sq_sum: float = 0.0

    def add(self, ts: float, size: int, forward: bool, syn: bool, fin: bool, rst: bool) -> None:
        if self.packets == 0:
            self.first_ts = ts
            self.last_ts = ts
        self.last_ts = ts
        self.packets += 1
        self.bytes_total += size
        self.lengths_sum += size
        self.lengths_sq_sum += size * size
        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += size
            if self.fwd_packets > 1:
                self.fwd_iat_sum += max(0.0, ts - self.fwd_last_ts)
            self.fwd_last_ts = ts
        else:
            self.bwd_packets += 1
            self.bwd_bytes += size
            if self.bwd_packets > 1:
                self.bwd_iat_sum += max(0.0, ts - self.bwd_last_ts)
            self.bwd_last_ts = ts
        self.syn_count += int(syn)
        self.fin_count += int(fin)
        self.rst_count += int(rst)

    def to_features(self, protocol_encoded: int) -> Dict[str, float]:
        duration_s = max(self.last_ts - self.first_ts, 1e-6)
        duration_us = duration_s * 1_000_000.0
        pps = self.packets / duration_s
        fwd_pps = self.fwd_packets / duration_s
        bwd_pps = self.bwd_packets / duration_s
        mean_len = self.lengths_sum / max(self.packets, 1)
        variance = max(0.0, self.lengths_sq_sum / max(self.packets, 1) - mean_len * mean_len)
        return {
            "flow_duration": duration_us,
            "fwd_packet_length_mean": self.fwd_bytes / max(self.fwd_packets, 1),
            "bwd_packet_length_mean": self.bwd_bytes / max(self.bwd_packets, 1),
            "flow_bytes_per_sec": self.bytes_total / duration_s,
            "flow_packets_per_sec": pps,
            "fwd_iat_mean": (self.fwd_iat_sum / max(self.fwd_packets - 1, 1)) * 1_000_000.0,
            "bwd_iat_mean": (self.bwd_iat_sum / max(self.bwd_packets - 1, 1)) * 1_000_000.0,
            "active_mean": duration_us,
            "idle_mean": 0.0,
            "fwd_packets_per_sec": fwd_pps,
            "bwd_packets_per_sec": bwd_pps,
            "packet_length_variance": variance,
            "fin_flag_count": float(self.fin_count),
            "syn_flag_count": float(self.syn_count),
            "rst_flag_count": float(self.rst_count),
            "protocol_encoded": float(protocol_encoded),
            "down_up_ratio": self.bwd_bytes / max(self.fwd_bytes, 1),
        }


class OnlineFlowTable:
    """Maintain short-lived flow records and emit finalized records."""

    PROTO = {"ICMP": 2, "TCP": 0, "UDP": 1}

    def __init__(self, idle_timeout: float = 1.0, max_packets: int = 5):
        self.idle_timeout = float(idle_timeout)
        self.max_packets = int(max_packets)
        self.flows = {}
        self.last_seen = {}
        self.metadata = {}
        self.sequence = 0

    def observe(self, src_ip: str, dst_ip: str, protocol: str, size: int,
                syn: bool = False, fin: bool = False, rst: bool = False,
                now: float | None = None, *, observation_id=1,
                src_port=0, dst_port=0, ground_truth="unknown", run_id="unspecified") -> list[dict]:
        now = monotonic() if now is None else float(now)
        proto = protocol.upper()
        key = (observation_id, src_ip, dst_ip, proto, int(src_port), int(dst_port), ground_truth, run_id)
        emitted = self.expire(now)
        if key not in self.flows:
            self.flows[key] = FlowStats(first_ts=now, last_ts=now)
            self.sequence += 1
            self.metadata[key] = dict(flow_id=f"{run_id}:{observation_id}:{self.sequence}",
                observation_id=observation_id, src_ip=src_ip, dst_ip=dst_ip,
                protocol=proto, src_port=int(src_port), dst_port=int(dst_port),
                ground_truth=ground_truth, run_id=run_id)
        self.flows[key].add(now, int(size), True, syn, fin, rst)
        self.last_seen[key] = now
        if self.flows[key].packets >= self.max_packets:
            emitted.append(self._finalize(key, "packet_window"))
        return emitted

    def _finalize(self, key, reason):
        stats = self.flows.pop(key)
        self.last_seen.pop(key, None)
        return {**stats.to_features(self.PROTO.get(key[3], 0)), **self.metadata.pop(key),
                "packet_count": stats.packets, "byte_count": stats.bytes_total,
                "first_ts": stats.first_ts, "last_ts": stats.last_ts, "end_reason": reason}

    def expire(self, now: float | None = None, force: bool = False) -> list[dict]:
        now = monotonic() if now is None else float(now)
        emitted = []
        for key in list(self.flows):
            if force or now - self.last_seen.get(key, now) >= self.idle_timeout:
                emitted.append(self._finalize(key, "flush" if force else "idle"))
        return emitted
