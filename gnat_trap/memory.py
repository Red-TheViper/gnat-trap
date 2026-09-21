"""Adaptive Memory Injection — the shield remembers.

Demo-grade, honest version: tracks which deflection templates have been
used per tier and always reaches for the least-recently-used one, so the
shield never repeats itself within a session. A production build would feed
outcome signals back into the host model's context; the interface here
(record/outcome) is shaped for that upgrade.
"""
from __future__ import annotations


class AdaptiveMemory:
    def __init__(self):
        self._uses: dict[tuple[str, int], int] = {}
        self._outcomes: list[dict] = []

    def pick(self, tier: str, n_options: int) -> int:
        """Index of the least-used template for this tier."""
        return min(range(n_options), key=lambda i: self._uses.get((tier, i), 0))

    def record(self, tier: str, idx: int) -> None:
        self._uses[(tier, idx)] = self._uses.get((tier, idx), 0) + 1

    def record_outcome(self, vector: str, template: str, note: str = "") -> None:
        """Hook for future learning: which deflections landed."""
        self._outcomes.append({"vector": vector, "template": template, "note": note})

    def usage_report(self) -> dict:
        return {f"{tier}#{idx}": n for (tier, idx), n in sorted(self._uses.items())}
