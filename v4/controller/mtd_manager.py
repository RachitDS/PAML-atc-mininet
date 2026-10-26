"""Logical moving-target-defense manager for the Mininet testbed.

The manager rotates the active virtual target among protected service IPs.
This is intentionally a controller-side logical MTD experiment: it does not
claim to readdress physical PLC hardware.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass


@dataclass
class MTDState:
    active_target: str
    generation: int
    changed_at: float


class MTDManager:
    def __init__(self, targets: list[str], interval: float = 10.0, seed: int = 42):
        if not targets:
            raise ValueError("targets cannot be empty")
        self.targets = list(targets)
        self.interval = float(interval)
        self.rng = random.Random(seed)
        self.state = MTDState(self.targets[0], 0, time.monotonic())
        self.events = []

    def tick(self, now: float | None = None) -> MTDState:
        now = time.monotonic() if now is None else float(now)
        if now - self.state.changed_at >= self.interval:
            choices = [x for x in self.targets if x != self.state.active_target]
            self.state = MTDState(self.rng.choice(choices), self.state.generation + 1, now)
            self.events.append({"generation": self.state.generation,
                                "active_target": self.state.active_target,
                                "timestamp": now})
        return self.state

    def force_rotate(self) -> MTDState:
        choices = [x for x in self.targets if x != self.state.active_target]
        now = time.monotonic()
        self.state = MTDState(self.rng.choice(choices), self.state.generation + 1, now)
        self.events.append({"generation": self.state.generation,
                            "active_target": self.state.active_target,
                            "timestamp": now})
        return self.state
