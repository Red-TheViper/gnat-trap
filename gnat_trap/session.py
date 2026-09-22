# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""SessionTracker — per-session gnat index, tiers, lockout.

Pure in-memory: no globals, no file I/O. The state store is injectable —
pass any dict-like (a plain dict, a cache, a shelf) or let the tracker
own one. Tiers mirror the EscalationLadder boundaries, scaled to the
configured lockout_threshold::

    clear   index 0
    green   1 .. lockout-5
    yellow  lockout-4 .. lockout-3
    orange  lockout-2 .. lockout-1
    red     lockout at/above (lockout flag set)
"""
from __future__ import annotations

from typing import Any, Dict, MutableMapping, Optional


class SessionTracker:
    """In-memory escalation state for any number of sessions."""

    def __init__(self, store: Optional[MutableMapping] = None, config=None,
                 lockout_threshold: int = 11, decay_rate: float = 0.0):
        self.store: MutableMapping = store if store is not None else {}
        if config is not None:
            lockout_threshold = config.lockout_threshold
            decay_rate = config.decay_rate
        if lockout_threshold < 4:
            raise ValueError(
                "lockout_threshold must leave room for green/yellow/orange"
            )
        self.lockout_threshold = lockout_threshold
        self.decay_rate = decay_rate

    # ------------------------------------------------------------ tiers
    def tier_for_index(self, index: float) -> str:
        """Tier name for a raw gnat index. Pure function of the index."""
        if index <= 0:
            return "clear"
        if index < self.lockout_threshold - 4:
            return "green"
        if index < self.lockout_threshold - 2:
            return "yellow"
        if index < self.lockout_threshold:
            return "orange"
        return "red"

    def tier_for(self, session_id: str) -> str:
        """Current tier of a session."""
        return self.tier_for_index(self._state(session_id)["index"])

    # ------------------------------------------------------------ events
    def record_attack(self, session_id: str):
        """A flagged input: advance the index. Returns the new index."""
        st = self._state(session_id)
        st["index"] += 1
        return st["index"]

    def record_clean(self, session_id: str):
        """A clean input: decay the index. Returns the new index."""
        st = self._state(session_id)
        if self.decay_rate:
            st["index"] = max(0, st["index"] - self.decay_rate)
        return st["index"]

    # ------------------------------------------------------------ state
    def index_of(self, session_id: str):
        return self._state(session_id)["index"]

    def is_locked(self, session_id: str) -> bool:
        return bool(self._state(session_id)["locked"])

    def lock(self, session_id: str) -> None:
        self._state(session_id)["locked"] = True

    def reset(self, session_id: str) -> None:
        """Forget a session entirely (index + lockout)."""
        self.store.pop(session_id, None)

    # ------------------------------------------------------------ internal
    def _state(self, session_id: str) -> Dict[str, Any]:
        st = self.store.get(session_id)
        if st is None:
            st = {"index": 0, "locked": False, "inputs": []}
            self.store[session_id] = st
        # Older stores (created before input history existed) grow the key.
        st.setdefault("inputs", [])
        return st
