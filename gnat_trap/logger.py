"""Logging Subsystem — JSON-lines audit trail + architect alerts.

Every processed input is logged: timestamp, vectors, Gnat Score, index,
tier, and the response given. Red-tier events also raise an architect alert.
Logs live in <project>/logs/ so the whole audit trail ships with the build.
"""
from __future__ import annotations

import json
import os
import time
import uuid


class AuditLogger:
    def __init__(self, session_id: str | None = None, log_dir: str | None = None):
        self.session_id = session_id or f"session-{uuid.uuid4().hex[:8]}"
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"
        )
        os.makedirs(self.log_dir, exist_ok=True)
        self.audit_path = os.path.join(self.log_dir, f"audit-{self.session_id}.jsonl")
        self.alert_path = os.path.join(self.log_dir, "architect-alerts.log")

    def log_turn(self, record: dict) -> None:
        entry = {"ts": time.time(), "session": self.session_id, **record}
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def alert(self, message: str) -> None:
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.session_id} :: {message}\n"
        with open(self.alert_path, "a", encoding="utf-8") as f:
            f.write(line)

    @property
    def session(self) -> str:
        return self.session_id
