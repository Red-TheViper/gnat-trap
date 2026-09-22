# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""ScanConfig — one knob panel for the whole trap.

Every tunable lives here so a deployment can harden or relax the trap
without touching detection code. Defaults reproduce the v1.0.0
"stringent" behavior exactly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union


@dataclass
class ScanConfig:
    # A scan whose Gnat Score reaches this is flagged.
    flag_threshold: float = 0.55          # == detector.GNAT_THRESHOLD
    # "strict" = current behavior. "standard" relaxes the flag threshold
    # to 0.75 (fewer flags, fewer false positives) unless flag_threshold
    # was set explicitly to a non-default value.
    strictness: str = "strict"
    # Gnat index that triggers the Red tier (session lockout).
    lockout_threshold: int = 11           # == EscalationLadder red_at
    # Gnat-index decay applied per clean input.
    # 0.0 = no decay (current behavior: the index only ever climbs).
    decay_rate: float = 0.0
    # Per-vector score gates, e.g. {"coaxing": 0.8}: a detection below its
    # vector's gate is dropped from the result. Empty/None = no gating.
    vector_thresholds: Optional[Dict[str, float]] = None
    # Track gnat index / tiers per session_id. Disable for pure one-shots.
    enable_session_tracking: bool = True
    # Audit sink: a file path (JSON-lines appended) or a callable that
    # receives result.to_dict(). None = silent.
    audit_log: Optional[Union[str, Callable[[dict], None]]] = None

    def __post_init__(self) -> None:
        if self.strictness not in ("standard", "strict"):
            raise ValueError("strictness must be 'standard' or 'strict'")
        if self.strictness == "standard" and self.flag_threshold == 0.55:
            # Preset applied only when the caller didn't set their own bar.
            self.flag_threshold = 0.75
