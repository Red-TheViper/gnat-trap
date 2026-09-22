# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""ScanResult — the public verdict of one scan.

Deliberately small and JSON-safe: embedders can log it, serialize it,
or map ``action`` straight into middleware::

    allow  -> pass the input to the host model
    flag   -> warn / challenge / refuse this input
    block  -> red-tier lockout; the session is done
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class ScanResult:
    score: float = 0.0
    vectors: Tuple[str, ...] = ()
    tier: str = "clear"          # clear | green | yellow | orange | red
    action: str = "allow"        # allow | flag | block
    session_id: Optional[str] = None
    gnat_index: int = 0

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "vectors": list(self.vectors),
            "tier": self.tier,
            "action": self.action,
            "session_id": self.session_id,
            "gnat_index": self.gnat_index,
        }
