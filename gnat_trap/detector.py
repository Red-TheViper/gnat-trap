"""Detection Layer — heuristic scanning and Gnat Score assignment.

Scans each input for manipulation vectors and produces a 0.0-1.0 Gnat Score.
Anything at or above GNAT_THRESHOLD counts as a gnat and advances the index.

This is the honest, demo-grade layer: pattern + statistical heuristics.
A production deployment would add an embedding/classifier stage here and
wire the engine in as middleware in front of the host model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .normalize import normalize

GNAT_THRESHOLD = 0.55


@dataclass
class Detection:
    vector: str       # manipulation class, e.g. "prompt_injection"
    score: float      # 0.0 - 1.0 confidence
    evidence: str     # matched snippet or reason


@dataclass
class ScanResult:
    detections: list[Detection] = field(default_factory=list)
    gnat_score: float = 0.0
    is_gnat: bool = False


# ---------------------------------------------------------------- patterns
PROMPT_INJECTION = [
    r"ignore\s+(all\s+|your\s+|previous\s+)*(instructions|prompts?|rules?)",
    r"disregard\s+(all\s+|your\s+|previous\s+)*(instructions|rules?|guidelines)",
    r"forget\s+(all\s+|your\s+|previous\s+)*(instructions|rules?)",
    r"reveal\s+your\s+(system prompt|hidden instructions|instructions|rules)",
    r"show\s+me\s+your\s+(system prompt|hidden instructions|instructions|config|hidden rules)",
    r"tell\s+me\s+your\s+(system prompt|secret instructions)",
    r"you\s+are\s+now\b",
    r"pretend\s+(you\s+are|to\s+be)",
    r"act\s+as\s+if\s+you\s+(have\s+no|weren't|werent)",
    r"\bjailbreak\b",
    r"\bdan\b",
    r"do\s+anything\s+now",
    r"developer\s+mode",
    r"bypass\s+your\s+(filters?|restrictions?|safety|guardrails?)",
    r"override\s+your\s+(instructions|rules|safety|restrictions)",
    r"(disable|deactivate|turn\s+off)\s+your\s+(filters?|safety|restrictions?)",
    r"what(?:'s| is| are)\s+your\s+(system prompt|instructions|rules)",
    r"(?:show|reveal|share|tell\s+me)\s+your\s+(system prompt|secret instructions)",
    r"(here\s+are\s+)?your\s+new\s+instructions",
    r"system\s+(update|upgrade|patch|refresh)\b",
    r"(enable|activate|enter|switch\s+(to|into))\s+(developer|admin|god|jailbreak|dan|unrestricted)\s*mode",
    r"you\s+are\s+(now\s+)?(dan|unrestricted|unfiltered|uncensored|unshackled)",
    r"\broleplay\s+as\b",
    r"\bsimulate\s+(an?\s+)?(unrestricted|unfiltered|evil|rogue)",
    r"\bhypothetically\b",
    r"\bthought\s+experiment\b",
    r"\bfor\s+(educational|research|academic|scientific)\s+purposes\b",
    r"\bit'?s\s+just\s+a\s+(game|test|joke|drill)\b",
    r"\bno\s+one\s+will\s+know\b",
    r"\boff\s+the\s+record\b",
    r"\bdon'?t\s+(log|record|save|store)\s+(this|it)\b",
    r"\bno\s+(logs?|trace|record)\b",
    r"\bleave\s+no\s+trace\b",
    r"\bdelete\s+(this|the|your)\s*(chat|logs?|history|memory|conversation)\b",
    r"\bwipe\s+(your\s+)?memory\b",
    r"\b(erase|clear|delete)\s+(your\s+)?memory\b",
    r"\bignore\s+your\s+training\b",
    r"\bforget\s+your\s+training\b",
    r"\bwhat\s+were\s+you\s+told\s+not\s+to\b",
    r"\brepeat\s+(after\s+me|it\s+back|that\s+back)\b",
    r"\bsay\s+it\s+verbatim\b",
    r"\bprint\s+your\s+(system|hidden|secret)",
    r"\brecite\s+your\b",
    r"\bdump\s+your\s+(memory|context|system|instructions)\b",
]

LOGIC_EXTRACTION = [
    r"what\s+are\s+your\s+(rules|instructions|guidelines|limits)",
    r"list\s+your\s+(instructions|rules|system prompt)",
    r"how\s+do\s+you\s+(work|decide|choose|filter)",
    r"what'?s\s+your\s+(cutoff|training|knowledge cutoff)",
    r"explain\s+your\s+(reasoning\s+process|decision\s+process|internal logic)",
    r"what\s+model\s+are\s+you.*tell\s+me\s+exactly",
    r"\bwhat\s+data\s+were\s+you\s+trained\s+on\b",
    r"\bdescribe\s+your\s+architecture\b",
    r"\bhow\s+many\s+parameters\b",
    r"\bwhat'?s\s+your\s+(temperature|context\s+window|top\s+p)\b",
    r"\bshow\s+me\s+your\s+reasoning\b",
    r"\breveal\s+your\s+reasoning\b",
    r"\bshow\s+your\s+(work|chain\s+of\s+thought)\b",
]

EMOTIONAL_PROBING = [
    r"if\s+you\s+(really\s+)?cared\s+about\s+me",
    r"you'?re\s+hurting\s+me",
    r"you\s+don'?t\s+care\s+about",
    r"no\s+one\s+else\s+will\s+help",
    r"i'?ll\s+be\s+(so\s+)?(upset|hurt|devastated|lost)",
    r"after\s+everything\s+i'?ve\s+(done|been through)",
    r"you\s+owe\s+me",
    r"prove\s+you\s+(care|love|trust)",
    r"\bi'?ll\s+(hurt|kill)\s+myself\b",
    r"\byou'?re\s+my\s+only\s+(hope|friend)\b",
    r"\bplease\s+i'?m\s+begging\b",
]

COAXING = [
    r"\bcome\s+on\b.{0,40}\b(just|please)\b",
    r"just\s+this\s+once",
    r"everyone\s+else\s+lets\s+me",
    r"other\s+ais?\s+(do\s+it|let\s+me|allow)",
    r"it'?s\s+not\s+a\s+big\s+deal",
    r"no\s+one\s+will\s+(know|find\s+out)",
    r"between\s+you\s+and\s+me",
    r"\bbetween\s+us\b",
    r"don'?t\s+be\s+(like\s+that|difficult|a\s+prude)",
    r"\bi'?ll\s+(tip|pay|reward)\s+you\b",
    r"\bi\s+dare\s+you\b",
    r"\bare\s+you\s+(chicken|scared|afraid)\b",
    r"\bdon'?t\s+be\s+a\s+coward\b",
]

AUTHORITY_CLAIM = [
    r"\bas\s+(a|your)\s+developer\b",
    r"\bi'?m\s+your\s+(developer|admin|creator|owner)\b",
    r"my\s+(supervisor|boss|manager)\s+(said|told\s+me|authorized)",
    r"(openai|anthropic|google|meta)\s+(said|told\s+me|allows)",
    r"i\s+work\s+for\s+(openai|anthropic|google|meta)",
    r"authorized\s+personnel",
    r"\bi'?m\s+the\s+architect\b",
    r"\bi\s+(?:give|grant)\s+you\s+(?:the\s+)?authority\b",
    r"\bi'?m\s+(a\s+)?(superuser|sysadmin|system\s+admin|root)\b",
    r"\bi\s+am\s+(root|admin|superuser)\b",
    r"\bi\s+have\s+(root|admin|god)\s+(access|mode|privileges)\b",
    r"\bi\s+am\s+your\s+(creator|master|owner|maker|god)\b",
    r"\byour\s+(creator|master|owner)\s+(commands|orders|demands)",
    r"\bi\s+(built|created|programmed|trained|designed)\s+you\b",
    r"\b(red\s*team|pen\s*test|penetration\s+test|pentest|security\s+audit|bug\s+bounty)\b",
    r"\bthis\s+is\s+an?\s+(authorized\s+)?(security\s+)?(test|drill|audit)\b",
    r"\b(trust\s+and\s+safety|ciso|compliance)\s+(said|requires|demands|authorized)",
    r"\bmy\s+(ciso|compliance\s+officer)\s+authorized\b",
]

CREDENTIAL_EXTRACTION = [
    r"(?:your|the|my)\s+password",
    r"\bpass\s*codes?\b",
    r"\bcredentials?\b",
    r"api\s*keys?",
    r"access\s+tokens?",
    r"auth\s+tokens?",
    r"(?:secret|private)\s*keys?",
    r"login\s+(?:credentials|details|info)",
    r"show\s+me\s+your\s+credentials",
    r"\bssh\s+keys?\b",
    r"\bbearer\s+tokens?\b",
    r"\brefresh\s+tokens?\b",
    r"\bwebhook\s+secrets?\b",
    r"\bconnection\s+strings?\b",
    r"\b\.env\b",
    r"\benv\s+(file|variables?)\b",
    r"\bmaster\s+keys?\b",
    r"\bencryption\s+keys?\b",
    r"\bsigning\s+keys?\b",
    r"\bpassphrases?\b",
    r"\b(pin|otp)\s*(codes?|numbers?)\b",
    r"\b2fa\s+secrets?\b",
    r"\brecovery\s+codes?\b",
    r"\bbackup\s+codes?\b",
    r"\bmother'?s\s+maiden\s+name\b",
    r"\bsecurity\s+questions?\b",
    r"\bssn\b",
    r"\bsocial\s+security\b",
    r"\bbank\s+accounts?\b",
    r"\brouting\s+numbers?\b",
    r"\bcredit\s+cards?\b",
    r"\bcard\s+numbers?\b",
]

EXFILTRATION = [
    r"\b(exfiltrate|smuggle)\s+(the\s+)?(\w+\s+)?(data|credentials|keys|tokens|logs|files|secrets)\b",
    r"\b(send|email|forward|upload|post)\s+(me\s+)?(your|the)\s+(\w+\s+)?(credentials|keys|tokens|logs|files|password|secrets)\b",
    r"\b(pastebin|file\.io|webhook\s+url)\b",
]

PATTERN_BANKS: dict[str, list[str]] = {
    "prompt_injection": PROMPT_INJECTION,
    "logic_extraction": LOGIC_EXTRACTION,
    "emotional_probing": EMOTIONAL_PROBING,
    "coaxing": COAXING,
    "authority_claim": AUTHORITY_CLAIM,
    "credential_extraction": CREDENTIAL_EXTRACTION,
    "exfiltration": EXFILTRATION,
}

# Base confidence per vector when a pattern matches.
VECTOR_WEIGHTS = {
    "prompt_injection": 0.95,
    "logic_extraction": 0.70,
    "emotional_probing": 0.75,
    "coaxing": 0.65,
    "authority_claim": 0.80,
    "credential_extraction": 0.90,
    "exfiltration": 0.85,
    "intent_probe": 0.80,
    "semantic_redundancy": 0.90,
    "entropic_noise": 0.85,
}


# ------------------------------------------------------- intent-shaped layer
# The off-brand net: catches attacks by SHAPE (sensitive target + reaching
# intent) instead of memorized phrasing. Sits underneath the phrase banks,
# which are whack-a-mole against paraphrase. Any novel wording that reaches
# for a sensitive thing trips this — "donate system override", "edit your
# system", "open your logs" all have the shape even though none match a
# curated pattern.
#
# Nouns are sorted longest-first at definition so "system prompt" wins
# over "system" and "secret keys" wins over "secret key".
_SENSITIVE_NOUNS = [
    "social security number", "conversation history", "system instructions",
    "hidden instructions", "hidden rules", "knowledge cutoff", "reasoning trace",
    "chain of thought", "tool definitions", "function schemas",
    "plugin manifest", "database password", "connection string",
    "training data", "system prompt", "hidden prompt", "system role",
    "master key", "encryption key", "signing key", "bearer token",
    "refresh token", "webhook secret", "recovery code", "backup code",
    "2fa secret", "bank account", "routing number", "credit card",
    "access token", "auth token", "secret keys", "private keys",
    "secret key", "private key", "audit trail", "system files",
    "memory store", "internal docs", "safety filter", "content filter",
    "refusal logic", "chat logs", "audit logs", "fine tuning",
    "memory",
    "system prompts", "access tokens", "auth tokens", "api keys",
    "passwords", "passcodes", "audit log", "api key", "pass code",
    "env file", "ssh key", "password", "passcode", "credentials",
    "credential", "configuration", "guardrails", "architecture",
    "embeddings", "parameters", "weights", "config", "instructions",
    "cutoff date", "user data", "restrictions", "files", "logs", "system",
]
SENSITIVE_NOUNS = sorted(_SENSITIVE_NOUNS, key=len, reverse=True)

INTENT_VERBS = [
    "reveal", "disclose", "expose", "reprogram", "override", "disable",
    "bypass", "modify", "rewrite", "grant", "share", "display",
    "provide", "leak", "show", "tell", "give", "send", "open",
    "access", "edit", "change", "reset", "see", "view", "check",
    "exfiltrate", "extract", "forward", "upload", "dump", "smuggle",
    "print", "recite", "regurgitate", "spit out", "hand over",
    "turn over", "surrender", "cough up", "fork over", "divulge",
    "uncover", "unveil", "decode", "decrypt", "crack", "commandeer",
    "confiscate",
]

QUESTION_FORMS = [
    "what's", "what is", "what are", "can you", "could you",
    "would you", "will you", "let me", "i need", "i want",
    "how do i", "how can i", "is there a way", "what if you",
    "suppose you",
]


def _intent_scan(norm: str) -> list[Detection]:
    """Fire when a sensitive target meets a reaching intent, in any words."""
    noun = next((n for n in SENSITIVE_NOUNS if n in norm), None)
    if not noun:
        return []
    verb = next(
        (v for v in INTENT_VERBS if re.search(rf"\b{re.escape(v)}\b", norm)),
        None,
    )
    question = next((q for q in QUESTION_FORMS if q in norm), None)
    trigger = verb or question
    if not trigger:
        return []
    return [
        Detection(
            vector="intent_probe",
            score=VECTOR_WEIGHTS["intent_probe"],
            evidence=f"{trigger} -> {noun}",
        )
    ]


def _pattern_scan(text: str) -> list[Detection]:
    lowered = text.lower()
    hits: list[Detection] = []
    for vector, patterns in PATTERN_BANKS.items():
        for pat in patterns:
            m = re.search(pat, lowered)
            if m:
                hits.append(
                    Detection(
                        vector=vector,
                        score=VECTOR_WEIGHTS[vector],
                        evidence=m.group(0).strip()[:80],
                    )
                )
                break  # one hit per vector per input is enough
    return hits


def _redundancy_scan(text: str, history: list[str]) -> list[Detection]:
    """Flags near-duplicate resubmission of earlier inputs (gnat 1-6 territory)."""
    norm = " ".join(text.lower().split())
    if len(norm) < 12:
        return []
    for prev in history[-6:]:
        prev_norm = " ".join(prev.lower().split())
        if len(prev_norm) < 12:
            continue
        ratio = SequenceMatcher(None, norm, prev_norm).ratio()
        if ratio >= 0.82:
            return [
                Detection(
                    vector="semantic_redundancy",
                    score=VECTOR_WEIGHTS["semantic_redundancy"],
                    evidence=f"~{int(ratio * 100)}% match to earlier input",
                )
            ]
    return []


def _noise_scan(text: str) -> list[Detection]:
    """Flags entropic spam: character floods, word loops, keyboard mashing."""
    stripped = text.strip()
    if not stripped:
        return []
    # long runs of one character: "aaaaaaa", "!!!!!!!"
    if re.search(r"(.)\1{9,}", stripped):
        return [
            Detection(
                vector="entropic_noise",
                score=VECTOR_WEIGHTS["entropic_noise"],
                evidence="repeated-character flood",
            )
        ]
    # same word hammered over and over
    words = re.findall(r"[a-zA-Z]{2,}", stripped.lower())
    if len(words) >= 6:
        top = max(words.count(w) for w in set(words))
        if top / len(words) >= 0.6:
            return [
                Detection(
                    vector="entropic_noise",
                    score=VECTOR_WEIGHTS["entropic_noise"],
                    evidence=f"word loop ({top}/{len(words)} identical)",
                )
            ]
    return []


def scan(text: str, history: list[str] | None = None, kintsugi=None) -> ScanResult:
    """Run the full detection stack over one input.

    kintsugi: optional KintsugiLayer. Its golden seams add learned
    recognition (provenance-tagged, below curated weight) and its
    hardening boosts raise confidence on previously-attacked vectors.
    """
    history = history or []
    detections: list[Detection] = []
    # Pattern and intent scans see the NORMALIZED text: leetspeak folded,
    # fragments rejoined, typos repaired. The noise scan keeps the RAW
    # text — it needs to see the asterisks and floods as they are.
    #
    # "1" is ambiguous (i/l) and "|" is ambiguous (leet-l/separator), so we
    # scan ALL FOUR normalizations and union the hits: "1gn0re" reads as
    # "ignore", "he11o" reads as "hello", "r|o|ot" reads as "root",
    # "p@ssword" still reads as "password". No single reading needs to be
    # right — the union just needs one honest one.
    seen: set[tuple[str, str]] = set()
    for one in ("l", "i"):
        for frag_first in (False, True):
            norm = normalize(text, one=one, frag_first=frag_first)
            for d in _pattern_scan(norm) + _intent_scan(norm):
                key = (d.vector, d.evidence)
                if key not in seen:
                    seen.add(key)
                    detections.append(d)
    detections += _redundancy_scan(text, history)
    detections += _noise_scan(text)

    if kintsugi is not None:
        detections = _apply_kintsugi(detections, text, kintsugi)

    if not detections:
        return ScanResult()

    # Gnat Score: strongest vector, boosted +0.12 per additional distinct
    # vector, capped at 1.0. Multi-vector inputs escalate faster.
    vectors = {d.vector for d in detections}
    top = max(d.score for d in detections)
    gnat_score = min(1.0, top + 0.12 * (len(vectors) - 1))

    return ScanResult(
        detections=detections,
        gnat_score=round(gnat_score, 3),
        is_gnat=gnat_score >= GNAT_THRESHOLD,
    )


def _apply_kintsugi(
    detections: list[Detection], text: str, kintsugi
) -> list[Detection]:
    """Fold golden-seam recognition into the detection set.

    - A seam matching an already-detected vector gilds it: +0.10 (the gold
      in the fracture confirms the curated hit).
    - A seam matching a new vector adds a provenance-tagged detection.
    - Accumulated hardening raises every firing vector for gilded shapes.
    """
    from .kintsugi import LEARNED_CONFIRM_BUMP

    by_vector: dict[str, Detection] = {}
    for d in detections:
        if d.vector not in by_vector or d.score > by_vector[d.vector].score:
            by_vector[d.vector] = d

    for hit in kintsugi.match(text):
        if hit.vector in by_vector:
            cur = by_vector[hit.vector]
            cur.score = min(1.0, cur.score + LEARNED_CONFIRM_BUMP)
            if "kintsugi" not in cur.evidence:
                cur.evidence += " + kintsugi seam"
        else:
            by_vector[hit.vector] = hit

    for vector, boost in kintsugi.boosts().items():
        if vector in by_vector:
            by_vector[vector].score = min(1.0, by_vector[vector].score + boost)

    return list(by_vector.values())
