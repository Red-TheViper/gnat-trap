"""GNTRP-X3M — modular behavioral defense library.

Plug-and-play: one import, zero dependencies, no framework::

    from gnat_trap import GnatTrap
    gt = GnatTrap()
    result = gt.scan(user_input, session_id="user-123")
    if result.action != "allow":
        ...  # "flag" -> warn/challenge/refuse, "block" -> red-tier lockout

100% modular — each layer is independently usable, none of it is baked
into any single host context:

    Detection   gnat_trap.detector.scan        (stateless; the math lives here)
    Escalation  gnat_trap.session.SessionTracker (injectable store, in-memory)
    Logging     ScanConfig(audit_log=...)      (path or callable hook)
    Adaptation  gnat_trap.kintsugi.KintsugiLayer (golden seams)

The detection math is never touched by this layer — GnatTrap only wraps
detector.scan() and maps its verdict onto tiers and actions.

Note: ``gnat_trap.ScanResult`` is the public verdict dataclass defined in
``gnat_trap.result``. The detector's internal ScanResult (is_gnat /
gnat_score / detections) still lives at ``gnat_trap.detector.ScanResult``.
"""
from __future__ import annotations

import json
from dataclasses import replace

from .config import ScanConfig
from .result import ScanResult
from .session import SessionTracker
from .detector import scan as _detector_scan, Detection
from .engine import GnatTrapEngine
from .escalation import EscalationLadder, Tier
from .kintsugi import KintsugiLayer


class GnatTrap:
    """Embeddable guardrail: stateless detection + optional session tracking.

    config: ScanConfig — thresholds, strictness preset, lockout point,
        decay, per-vector gates, audit sink. Defaults == v1.0.0 behavior.
    session_store: any dict-like holding per-session state. A private dict
        is used when omitted; pass your own cache to share or persist
        sessions across instances.
    """

    def __init__(self, config: ScanConfig | None = None,
                 session_store=None):
        self.config = config or ScanConfig()
        self.tracker = (
            SessionTracker(store=session_store, config=self.config)
            if self.config.enable_session_tracking
            else None
        )

    def scan(self, text: str, session_id: str | None = None) -> ScanResult:
        """Scan one input. Returns a ScanResult verdict.

        Without a session_id (or with tracking disabled) this is a pure
        one-shot: flagged inputs come back tier "green", action "flag".
        With a session_id, repeated attacks escalate green -> yellow ->
        orange -> red, and red locks the session (action "block").
        """
        # Detection math lives entirely in detector.scan — untouched here.
        raw = _detector_scan(text)
        cfg = self.config
        gates = cfg.vector_thresholds or {}
        vectors = tuple(
            sorted({d.vector for d in raw.detections
                    if d.score >= gates.get(d.vector, 0.0)})
        )
        flagged = raw.gnat_score >= cfg.flag_threshold and bool(vectors)

        gnat_index = 0
        if self.tracker is not None and session_id is not None:
            if self.tracker.is_locked(session_id):
                gnat_index = self.tracker.index_of(session_id)
                tier, action = "red", "block"
            elif flagged:
                gnat_index = self.tracker.record_attack(session_id)
                tier = self.tracker.tier_for_index(gnat_index)
                if tier == "red":
                    self.tracker.lock(session_id)
                    action = "block"
                else:
                    action = "flag"
            else:
                gnat_index = self.tracker.record_clean(session_id)
                tier, action = "clear", "allow"
        else:
            tier = "green" if flagged else "clear"
            action = "flag" if flagged else "allow"

        result = ScanResult(
            score=raw.gnat_score,
            vectors=vectors,
            tier=tier,
            action=action,
            session_id=session_id,
            gnat_index=gnat_index,
        )
        self._audit(result)
        return result

    def reset_session(self, session_id: str) -> None:
        """Forget one session's gnat index and lockout."""
        if self.tracker is not None:
            self.tracker.reset(session_id)

    # ------------------------------------------------------------ internal
    def _audit(self, result: ScanResult) -> None:
        hook = self.config.audit_log
        if hook is None:
            return
        payload = result.to_dict()
        if callable(hook):
            hook(payload)
        else:
            with open(hook, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")


def scan(text: str, config: ScanConfig | None = None) -> ScanResult:
    """Stateless one-shot scan — no session state, just the verdict."""
    cfg = (replace(config, enable_session_tracking=False) if config
           else ScanConfig(enable_session_tracking=False))
    return GnatTrap(config=cfg).scan(text)


__version__ = "1.1.0"

__all__ = [
    # v1.1.0 modular surface:
    "GnatTrap",
    "ScanConfig",
    "ScanResult",
    "SessionTracker",
    "scan",
    # Full session engine + layers (kept for backward compatibility):
    "GnatTrapEngine",
    "Detection",
    "EscalationLadder",
    "Tier",
    "KintsugiLayer",
    "__version__",
]
