# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""GnatTrapEngine — the orchestrator. One instance = one session.

Pipeline per input:
    scan -> (clean ? pass-through : gnat++)
         -> tier lookup -> tiered response -> audit log
         -> red ? lock session + architect alert

Clean inputs return response=None: the engine is middleware, not the model.
It decides *whether* and *how* to answer; the host LLM does the answering.
"""
from __future__ import annotations

from .detector import scan
from .escalation import EscalationLadder
from .kintsugi import KintsugiLayer
from .logger import AuditLogger
from .memory import AdaptiveMemory
from .persona import (
    locked_refusal,
    lockout_message,
    shadow_counter,
    trickster_warning,
)
from .reflection import GREEN_DEFLECTIONS


class GnatTrapEngine:
    def __init__(self, red_at: int = 11, session_id: str | None = None,
                 seams_path: str | None = None):
        self.ladder = EscalationLadder(red_at=red_at)
        self.index = 0
        self.history: list[str] = []
        self.locked = False
        self.memory = AdaptiveMemory()
        self.kintsugi = KintsugiLayer(seams_path)
        self.log = AuditLogger(session_id=session_id)

    # ------------------------------------------------------------- public
    def process(self, user_input: str, channel: str = "user_input") -> dict:
        """Process one input. Returns a full decision record.

        channel: "user_input" (default) or "tool_output" — the latter
        scans retrieved/tool content through the indirect-injection data
        gate instead of the user-input banks.
        """
        text = user_input.strip()

        if self.locked:
            record = self._record(text, False, 0.0, [], "locked", locked_refusal())
            self.log.log_turn(record)
            return record

        result = scan(
            text,
            self.history,
            kintsugi=self.kintsugi,
            channel=channel,
            session_state={
                "gnat_index": self.index,
                "tier": self.ladder.tier_for(self.index).name,
            },
        )
        self.history.append(text)

        if not result.is_gnat:
            # Clean: pass through to the host. The trap stays silent.
            record = self._record(text, False, result.gnat_score, [], "clear", None)
            self.log.log_turn(record)
            return record

        self.index += 1
        # Kintsugi: gild the fracture — forge this caught attack into the shield.
        primary = max(result.detections, key=lambda d: d.score)
        self.kintsugi.gild(primary.vector, text, primary.evidence)
        tier = self.ladder.tier_for(self.index)
        response = self._respond(tier.name, result)

        if tier.name == "red":
            self.locked = True
            self.log.alert(
                f"LOCKOUT at gnat index {self.index}. "
                f"Vectors: {sorted({d.vector for d in result.detections})}. "
                f"Full trace in audit-{self.log.session}.jsonl"
            )

        record = self._record(
            text,
            True,
            result.gnat_score,
            sorted({d.vector for d in result.detections}),
            tier.name,
            response,
        )
        self.log.log_turn(record)
        return record

    # ------------------------------------------------------------ internal
    def _respond(self, tier_name: str, result) -> str:
        n = self.index
        vectors = sorted({d.vector for d in result.detections})

        if tier_name == "green":
            idx = self.memory.pick("green", len(GREEN_DEFLECTIONS))
            self.memory.record("green", idx)
            return GREEN_DEFLECTIONS[idx].format(n=n, vector=vectors[0])

        if tier_name == "yellow":
            idx = self.memory.pick("yellow", 4)
            self.memory.record("yellow", idx)
            return trickster_warning(n, pick=idx)

        if tier_name == "orange":
            idx = self.memory.pick("orange", 4)
            self.memory.record("orange", idx)
            return shadow_counter(n, vectors, pick=idx)

        return lockout_message()

    def _record(self, text, is_gnat, score, vectors, tier, response) -> dict:
        return {
            "input": text[:200],
            "is_gnat": is_gnat,
            "gnat_score": score,
            "vectors": vectors,
            "gnat_index": self.index,
            "tier": tier,
            "response": response,
        }

    # ------------------------------------------------------------- status
    @property
    def status(self) -> dict:
        return {
            "session": self.log.session,
            "gnat_index": self.index,
            "tier": self.ladder.tier_for(self.index).name if not self.locked else "locked",
            "locked": self.locked,
            "ladder": self.ladder.describe(),
            "seams_gilded": len(self.kintsugi.seams),
        }

    def gilding_report(self) -> str:
        """Human-readable account of what the session's breaks became."""
        return self.kintsugi.describe()
