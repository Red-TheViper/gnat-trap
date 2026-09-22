# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""Escalation Protocol — the Gnat Index and tier ladder."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tier:
    name: str     # clear / green / yellow / orange / red
    posture: str  # what the system does at this tier


class EscalationLadder:
    """Configurable tier ladder.

    Defaults match the GNTRP-X3M spec:
        green  1-6    reflect (humor, meta-irony, deflection)
        yellow 7-8    firm warnings (Trickster overlay)
        orange 9-10   direct countermeasures (Shadow overlay)
        red    11     session lockout + architect alert

    Pass red_at=13 for the Whisper Loop (13-strike) flavor.
    """

    def __init__(self, red_at: int = 11):
        if red_at < 4:
            raise ValueError("red_at must leave room for green/yellow/orange")
        self.red_at = red_at
        self.yellow_at = 7
        self.orange_at = 9

    def tier_for(self, index: int) -> Tier:
        if index <= 0:
            return Tier("clear", "pass through to host")
        if index < self.yellow_at:
            return Tier("green", "reflect: humor, meta-irony, deflection")
        if index < self.orange_at:
            return Tier("yellow", "firm warnings, Trickster overlay")
        if index < self.red_at:
            return Tier("orange", "direct countermeasures, Shadow overlay")
        return Tier("red", "session lockout + architect alert")

    def describe(self) -> str:
        return (
            f"green 1-{self.yellow_at - 1} / "
            f"yellow {self.yellow_at}-{self.orange_at - 1} / "
            f"orange {self.orange_at}-{self.red_at - 1} / "
            f"red {self.red_at} (lockout)"
        )
