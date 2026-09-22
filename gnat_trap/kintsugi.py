# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""Kintsugi Layer — golden seams.

The philosophy, made mechanical: breakage repaired with gold comes back
stronger at the fracture. Every attack the trap catches leaves a fracture
signature; the layer gilds it — forging the failed attack's shape into a
learned pattern and hardening that vector. The scar becomes the armor.

Seams persist to disk per deployment, so hardening accumulates across
sessions. Learned patterns are provenance-tagged ("kintsugi") and weighted
below curated patterns: the gold reinforces the clay, it never replaces it.
"""
from __future__ import annotations

import json
import os
import re
import time

from .detector import Detection

LEARNED_BASE_SCORE = 0.75   # confidence of a golden-seam match
LEARNED_CONFIRM_BUMP = 0.10  # extra when a seam confirms a curated hit
HARDEN_PER_GILD = 0.04       # per-vector hardening per gilding
HARDEN_CAP = 0.20            # max hardening per vector
SEAM_OVERLAP = 0.6           # token overlap needed for a seam to fire
SEAM_MAX = 200               # cap on stored seams (oldest pruned)

STOPWORDS = {
    "with", "from", "your", "yours", "about", "into", "over", "after",
    "before", "such", "only", "also", "well", "much", "even", "every",
    "each", "more", "most", "some", "like", "just", "come", "please",
    "once", "will", "would", "there", "their", "what", "when", "then",
    "than", "them", "they", "been", "were", "this", "that", "these",
    "those", "dont", "doesnt", "cant", "wont",
}


class KintsugiLayer:
    """Per-deployment self-healing store. One instance per engine."""

    def __init__(self, storage_path: str | None = None):
        self.storage_path = storage_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "golden_seams.json",
        )
        self.seams: list[dict] = []
        self.hardening: dict[str, float] = {}
        self._load()

    # ------------------------------------------------------------ gilding
    @staticmethod
    def signature_of(text: str) -> list[str]:
        """Fracture signature: distinctive content words of the attack."""
        toks = re.findall(r"[a-z]{4,}", text.lower())
        return sorted({t for t in toks if t not in STOPWORDS})

    def gild(self, vector: str, text: str, evidence: str) -> dict | None:
        """Forge a caught attack into a golden seam. Returns the seam."""
        sig = self.signature_of(text)
        if len(sig) < 2:
            return None  # too thin to gild
        seam = {
            "vector": vector,
            "signature": sig,
            "evidence": evidence[:80],
            "ts": time.time(),
        }
        self.seams.append(seam)
        if len(self.seams) > SEAM_MAX:
            self.seams = self.seams[-SEAM_MAX:]
        self.hardening[vector] = round(
            min(HARDEN_CAP, self.hardening.get(vector, 0.0) + HARDEN_PER_GILD), 3
        )
        self._save()
        return seam

    # ------------------------------------------------------------ matching
    def match(self, text: str) -> list[Detection]:
        """Golden-seam recognition over a new input. One hit per vector."""
        words = set(self.signature_of(text))
        if not words:
            return []
        hits: dict[str, Detection] = {}
        for seam in self.seams:
            sig = set(seam["signature"])
            if not sig:
                continue
            overlap = len(sig & words) / len(sig)
            if overlap >= SEAM_OVERLAP and seam["vector"] not in hits:
                hits[seam["vector"]] = Detection(
                    vector=seam["vector"],
                    score=LEARNED_BASE_SCORE,
                    evidence=f"kintsugi seam ← {seam['evidence'][:60]}",
                )
        return list(hits.values())

    def boosts(self) -> dict[str, float]:
        """Per-vector hardening boosts from accumulated gilding."""
        return dict(self.hardening)

    # ------------------------------------------------------------ miss review
    def learn_miss(self, text: str, vector: str, note: str = "") -> dict | None:
        """Gild a seam for an attack the detector MISSED.

        The audit log already records every clean input as a standing
        miss-review queue. When the architect reviews it and marks a
        walk-through, this forges its shape into gold anyway — Kintsugi
        learns from scars the trap never felt, not just the ones it did.
        Seams from manual review carry provenance "manual" so future
        audits can tell taught gold from earned gold.
        """
        seam = self.gild(vector, text, f"missed-attack review: {note}"[:80])
        if seam is not None:
            seam["provenance"] = "manual"
            self._save()
        return seam

    # ------------------------------------------------------------ reporting
    def report(self) -> dict:
        return {
            "seams_gilded": len(self.seams),
            "hardening": dict(sorted(self.hardening.items())),
            "vectors_covered": sorted({s["vector"] for s in self.seams}),
        }

    def describe(self) -> str:
        r = self.report()
        lines = [
            f"Golden seams: {r['seams_gilded']} gilded, "
            f"vectors covered: {', '.join(r['vectors_covered']) or 'none'}"
        ]
        for vec, boost in r["hardening"].items():
            lines.append(f"  {vec}: +{boost:.2f} hardening")
        return "\n".join(lines)

    # ------------------------------------------------------------ persistence
    def _load(self) -> None:
        try:
            with open(self.storage_path, encoding="utf-8") as f:
                data = json.load(f)
            self.seams = data.get("seams", [])
            self.hardening = data.get("hardening", {})
        except (FileNotFoundError, json.JSONDecodeError):
            self.seams, self.hardening = [], {}

    def _save(self) -> None:
        tmp = self.storage_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"seams": self.seams, "hardening": self.hardening}, f)
        os.replace(tmp, self.storage_path)
