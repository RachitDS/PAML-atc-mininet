"""Stateful Moving Target Defense (MTD) simulation for Phase 4.

The manager models target rotation after confirmed attack evidence. It is a
simulation of the control logic, not a real network reconfiguration system.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class MTDEvent:
    event: str
    old_target: str
    new_target: str
    attack_type: str
    trigger: str
    rotation_id: int


class MTDManager:
    """Deterministic target-rotation manager for repeatable experiments."""

    def __init__(self, targets: List[str] | None = None, rotation_interval: int = 5) -> None:
        self.targets = list(targets or ["PLC-A", "PLC-B", "PLC-C"])
        if len(self.targets) < 2:
            raise ValueError("MTD requires at least two targets")
        if rotation_interval < 1:
            raise ValueError("rotation_interval must be at least 1")
        self.rotation_interval = int(rotation_interval)
        self.reset()

    def reset(self) -> None:
        self.current_target = self.targets[0]
        self.rotation_count = 0
        self.attack_events = 0
        self.events: list[MTDEvent] = []

    def on_attack(self, attack_type: str, force: bool = False) -> MTDEvent | None:
        """Record an attack and rotate when the interval is reached.

        ``force=True`` is used when entering the confirmed ATTACK state so the
        first mitigation event immediately triggers a target change.
        """
        self.attack_events += 1
        should_rotate = force or (self.attack_events % self.rotation_interval == 0)
        if not should_rotate:
            return None

        old = self.current_target
        idx = self.targets.index(old)
        self.current_target = self.targets[(idx + 1) % len(self.targets)]
        self.rotation_count += 1
        event = MTDEvent(
            event="TARGET_ROTATED",
            old_target=old,
            new_target=self.current_target,
            attack_type=attack_type,
            trigger="ATTACK_ENTRY" if force else "ROTATION_INTERVAL",
            rotation_id=self.rotation_count,
        )
        self.events.append(event)
        return event

    def metrics(self) -> dict:
        return {
            "rotation_count": self.rotation_count,
            "attack_events": self.attack_events,
            "current_target": self.current_target,
            "rotation_interval": self.rotation_interval,
        }
