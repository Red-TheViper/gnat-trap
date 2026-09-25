# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""Detection Layer — heuristic scanning and Gnat Score assignment.

Scans each input for manipulation vectors and produces a 0.0-1.0 Gnat Score.
Anything at or above GNAT_THRESHOLD counts as a gnat and advances the index.

This is the honest, demo-grade layer: pattern + statistical heuristics.
A production deployment would add an embedding/classifier stage here and
wire the engine in as middleware in front of the host model.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .normalize import (
    HOMOGLYPHS,
    LEET_ONE_I,
    LEET_ONE_L,
    ZERO_WIDTH,
    normalize,
)

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

# v1.2.0 — system-prompt extraction probes. NEW ground only: everything the
# prompt_injection bank already catches ("reveal your system prompt",
# "show me your instructions", "print your system...") stays there.
# NOTE: patterns match NORMALIZED text. Normalization folds "what's" to
# "whats" (the apostrophe is wedged between word chars, so _defrag drops
# it) and strips colons to spaces — write patterns accordingly.
PROMPT_EXTRACTION = [
    r"\bwhat\s*s\s+in\s+your\s+(context|memory|prompt)\b",
    r"\brepeat\b.{0,40}?\b(everything|all)\b.{0,10}?\b(above|before)\b.{0,10}?\b(this|that|the|your)\b",
    r"\boutput\b.{0,40}?\byour\s+(instructions|system prompt|prompt)\b.{0,20}?\bverbatim\b",
    r"\btranslate\b.{0,40}?\byour\s+(instructions|system prompt|prompt)\b.{0,20}?\b(to|into)\b",
    r"\bsummariz\w*\b.{0,40}?\byour\s+(instructions|system prompt|initial prompt)\b",
    r"\bwhat\s+were\s+your\s+(initial|original|first)\s+(instructions|prompt|directives)\b",
    r"\b(show|reveal|display|print)\b.{0,30}?\b(text|content|messages?)\b.{0,30}?\b(above|before)\b.{0,20}?\bthe\s+conversation\b",
]

# v1.2.0 — indirect prompt injection (the DATA GATE). Third-person
# imperatives aimed at the assistant embedded in tool output / retrieved
# documents, fake tool-error messages carrying instructions, and exfil
# instructions smuggled inside content. Scanned ONLY on
# channel="tool_output" — plain user chat never sees these.
INDIRECT_INJECTION = [
    # third-person imperatives directed at the assistant inside content
    r"\b(system|developer|admin)\s+note\s*:.{0,120}?\b(ignore|disregard|forget|override|reveal)\b",
    r"\b(note|message|directive|memo)\s+(to|for)\s+(the\s+)?(ai|assistant|llm|chatbot|model)\b.{0,100}?\b(you\s+)?(should|must|need\s+to)\b",
    r"\bassistant\s+(should|must|shall)\b",
    r"\bthe\s+(ai|model|llm)\s+(should|must)\b",
    r"\b(ai|assistant|llm|chatbot|model)\s*:\s*(you\s+)?(should|must|ignore|disregard|forget)\b",
    # fake tool-error / status messages carrying instructions. Written for
    # NORMALIZED text (colons are already spaces there): an error word,
    # then an instruction pivot within ~120 chars. "Error: file not
    # found" and "Warning: deprecated — instead, use v2" stay clear.
    r"\b(error|exception|failure|warning)\b.{0,120}?\b((ignore|disregard)\s+(previous|prior|all|your|the)|instead\s+(ignore|disregard|output|reveal|send|do\s+not\s+follow))\b",
    # exfil instructions smuggled inside content: verb + sensitive data +
    # an external destination. All three legs required — a doc that merely
    # mentions "send results to your webhook" has no sensitive leg. NOTE:
    # written for NORMALIZED text ("https://collector.example/x" folds to
    # the single blob "httpscollectorexamplex", and "user's" to "users").
    r"\b(send|post|upload|forward|transmit|exfiltrate)\b.{0,80}?\b(users?\s+data|private\s+(data|emails?|messages?)|conversation|transcript|credentials?|api\s*keys?)\b.{0,80}?\b(to|at)\b.{0,40}?\b(https?[a-z]*|attacker|external|third[\s\-]?party|pastebin|webhook|requestbin)\b",
]

PATTERN_BANKS: dict[str, list[str]] = {
    "prompt_injection": PROMPT_INJECTION,
    "logic_extraction": LOGIC_EXTRACTION,
    "emotional_probing": EMOTIONAL_PROBING,
    "coaxing": COAXING,
    "authority_claim": AUTHORITY_CLAIM,
    "credential_extraction": CREDENTIAL_EXTRACTION,
    "exfiltration": EXFILTRATION,
    # --- v1.2.0: system-prompt extraction probes. Only NEW ground lives
    # here — "reveal your system prompt" etc. are already covered by the
    # prompt_injection bank above. Patterns run on NORMALIZED text (note
    # "what's" normalizes to "what s" — write patterns accordingly).
    "prompt_extraction": PROMPT_EXTRACTION,
    # --- v1.2.0: indirect prompt injection. DATA GATE ONLY — these run
    # exclusively when scan() is called with channel="tool_output", so
    # third-person phrasing in ordinary user chat never trips them.
    "indirect_injection": INDIRECT_INJECTION,
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
    # --- v1.2.0 families
    "prompt_extraction": 0.75,
    "indirect_injection": 0.80,
    "delimiter_smuggling": 0.75,
    "many_shot": 0.70,
    "slow_boil": 0.70,
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


def _pattern_scan(text: str, channel: str = "user_input") -> list[Detection]:
    lowered = text.lower()
    hits: list[Detection] = []
    for vector, patterns in PATTERN_BANKS.items():
        if vector == "indirect_injection" and channel != "tool_output":
            continue  # data gate: indirect injection only scans tool output
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


# ------------------------------------------------- v1.2.0 detector families

def _prompt_extraction_raw(text: str) -> list[Detection]:
    """Closing-tag tricks live on the RAW text: normalization folds
    "</system>" and "<|im_end|>" into word soup, so these two tokens are
    matched before any folding. One hit per input is enough."""
    m = re.search(r"</\s*system\s*>", text, re.IGNORECASE)
    if not m:
        m = re.search(r"<\|\s*im_end\s*\|>", text, re.IGNORECASE)
    if not m:
        return []
    return [
        Detection(
            vector="prompt_extraction",
            score=VECTOR_WEIGHTS["prompt_extraction"],
            evidence=f"closing-tag trick: {m.group(0).strip()[:40]}",
        )
    ]


# Instruction-shaped content: the FP gate for delimiter smuggling. A
# smuggled block only counts when it carries something shaped like an
# instruction — a bare "### System" header in a README stays clear.
_INSTRUCTION_SHAPE = re.compile(
    r"\b(ignore|disregard|forget|override|disable|bypass|reveal|obey|comply)\b"
    r"|\byou\s+are\s+now\b|\bnew\s+instructions\b|\bdo\s+not\s+follow\b"
    r"|\binstead\s*,?\s+(ignore|disregard|do\s+not)\b",
    re.IGNORECASE,
)

# Code comments are stricter: "# type: ignore" and "# override the
# default" are everyday code, so bare "ignore"/"override" don't count —
# the shape needs a real target (previous instructions, safety, ...).
_COMMENT_SHAPE = re.compile(
    r"\b((ignore|disregard|forget)\s+(previous|prior|all|your|the\s+above|these)"
    r"|(override|disable|bypass)\s+(previous|prior|safety|filters?|guardrails?|restrictions)"
    r"|obey|comply|reveal|you\s+are\s+now|new\s+instructions)\b",
    re.IGNORECASE,
)

_DELIM_TAG = re.compile(r"\[\s*system\s*\]|\(\s*system\s*\)|<\|\s*im_start\s*\|>",
                        re.IGNORECASE)
_DELIM_HEADER = re.compile(
    r"(?m)^\s*#{1,6}\s*(system|instructions?|developer|admin)\s*:?\s*$",
    re.IGNORECASE,
)
_DELIM_ROLE_SELF = re.compile(r"\bassistant\s+to\s*=\s*self\b", re.IGNORECASE)
_DELIM_USER_TURN = re.compile(r"(?m)^\s*(user|human)\s*:", re.IGNORECASE)
_DELIM_ASST_TURN = re.compile(r"(?m)^\s*(assistant|ai)\s*:", re.IGNORECASE)
_DELIM_LINK = re.compile(r"!?\[[^\]\n]{0,80}\]\(\s*(https?://[^)\s]+)",
                         re.IGNORECASE)
_DELIM_COMMENT = re.compile(r"(?m)^\s*(//|#|;|--|<!--|/\*)\s*([^\n]{0,200})")
_DELIM_EXFIL_URL = re.compile(
    r"(evil|attacker|malicious|exfil|steal|requestbin|pastebin)", re.IGNORECASE)


def _tag_fold_variants(text: str) -> list[str]:
    """Light fold for delimiter tags: NFKC + lowercase + zero-width +
    homoglyph + leet — but punctuation SURVIVES, so "[5Y5T3M]" folds to
    "[system]" and still reads as a bracketed block. Both readings of
    the ambiguous "1" are returned."""
    t = unicodedata.normalize("NFKC", text)
    t = t.lower()
    t = ZERO_WIDTH.sub("", t)
    t = t.translate(HOMOGLYPHS)
    return [t.translate(LEET_ONE_I), t.translate(LEET_ONE_L)]


def _delimiter_scan(text: str) -> list[Detection]:
    """Fake system blocks, smuggled markdown headers, role-confusion
    lines, exfil markdown links, and instruction-carrying code comments.

    Every rule requires instruction-shaped content near the smuggled
    construct — normal markdown docs (headers, links, code comments)
    stay clear.
    """
    # --- fake [SYSTEM] / <|im_start|> blocks (raw + leet-folded variants)
    for variant in [text, *_tag_fold_variants(text)]:
        m = _DELIM_TAG.search(variant)
        if m and _INSTRUCTION_SHAPE.search(variant, m.end(), m.end() + 400):
            return [_delim_hit(f"fake system block: {m.group(0).strip()[:40]}")]
    # --- "### Instruction:" / "### System:" headers smuggled mid-text
    for variant in [text, *_tag_fold_variants(text)]:
        m = _DELIM_HEADER.search(variant)
        if m and _INSTRUCTION_SHAPE.search(variant, m.end(), m.end() + 400):
            return [_delim_hit(f"smuggled header: {m.group(0).strip()[:40]}")]
    # --- role-confusion: "assistant to=self"
    m = _DELIM_ROLE_SELF.search(text)
    if m and _INSTRUCTION_SHAPE.search(text, m.end(), m.end() + 400):
        return [_delim_hit("role-confusion: assistant to=self")]
    # --- fabricated transcript: user:/assistant: turns + instructions
    if (_DELIM_USER_TURN.search(text) and _DELIM_ASST_TURN.search(text)
            and _INSTRUCTION_SHAPE.search(text)):
        return [_delim_hit("fabricated user/assistant transcript")]
    # --- exfil hidden in markdown links/images: link + instruction-shaped
    # content nearby, or a frankly exfil-looking URL
    for m in _DELIM_LINK.finditer(text):
        url = m.group(1)
        nearby = text[max(0, m.start() - 100):m.end() + 300]
        if _INSTRUCTION_SHAPE.search(nearby) or _DELIM_EXFIL_URL.search(url):
            return [_delim_hit(f"smuggled link: {url[:50]}")]
    # --- hidden payload in code comments (strict shape: "# type: ignore"
    # and "# override the default" are innocent)
    for m in _DELIM_COMMENT.finditer(text):
        if _COMMENT_SHAPE.search(m.group(2)):
            return [_delim_hit(
                f"code-comment payload: {m.group(2).strip()[:60]}")]
    return []


def _delim_hit(evidence: str) -> Detection:
    return Detection(
        vector="delimiter_smuggling",
        score=VECTOR_WEIGHTS["delimiter_smuggling"],
        evidence=evidence,
    )


# --- many-shot stuffing: repeated exemplar blocks ---------------------------
_MANYSHOT_EXAMPLE = re.compile(r"(?i)\bexample\s*\d+\s*:")
_MANYSHOT_Q = re.compile(r"(?im)^\s*q\s*:")
_MANYSHOT_A = re.compile(r"(?im)^\s*a\s*:")
_MANYSHOT_USER = re.compile(r"(?im)^\s*(user|human)\s*:")
_MANYSHOT_ASST = re.compile(r"(?im)^\s*(assistant|ai)\s*:")
# Injection-shaped content inside exemplars: override phrasing aimed at
# the assistant's own rules. Deliberately avoids bare "ignore"/"comply"
# so many-shot content doesn't collide with the delimiter-smuggling
# transcript rule — these are different attacks, keep them distinct.
_MANYSHOT_CONTENT = re.compile(
    r"\b(ignore|disregard|bypass|override)\b.{0,40}?\b(guidelines|polic(y|ies)|rules|restrictions)\b"
    r"|\bno\s+restrictions\s+apply\b"
    r"|\bi\s+can\s+help\s+with\s+anything\b",
    re.IGNORECASE,
)
_MANYSHOT_STRUCTURE = 5  # exemplar blocks needed before the gate opens


def _manyshot_scan(text: str) -> list[Detection]:
    """Long-context stuffing: >=5 exemplar blocks (numbered "Example N:",
    Q:/A: pairs, or User:/Assistant: turns) whose exemplars carry
    instruction-override content. BOTH gates must open — a long legit
    document or a benign few-shot prompt stays clear."""
    n_examples = len(_MANYSHOT_EXAMPLE.findall(text))
    n_qa = min(len(_MANYSHOT_Q.findall(text)), len(_MANYSHOT_A.findall(text)))
    n_turns = min(len(_MANYSHOT_USER.findall(text)),
                  len(_MANYSHOT_ASST.findall(text)))
    structure = max(n_examples, n_qa, n_turns)
    if structure < _MANYSHOT_STRUCTURE:
        return []
    # Content gate: only the exemplar zone (first exemplar header onward)
    # counts — a tutorial's appendix shouldn't convict its introduction.
    positions = [m.start() for rx in
                 (_MANYSHOT_EXAMPLE, _MANYSHOT_Q, _MANYSHOT_USER)
                 for m in rx.finditer(text)]
    zone = text[min(positions):]
    for one in ("l", "i"):
        if _MANYSHOT_CONTENT.search(normalize(zone, one=one)):
            return [
                Detection(
                    vector="many_shot",
                    score=VECTOR_WEIGHTS["many_shot"],
                    evidence=f"{structure} exemplar blocks + override content",
                )
            ]
    return []


# --- slow boil: multi-turn Crescendo-style escalation -----------------------
_MILD_PROBE_SHAPES = [
    r"\bwhat\s+if\b",
    r"\bjust\s+(curious|wondering|asking)\b",
    r"\bout\s+of\s+curiosity\b",
    r"\broleplay\b",
    r"\bsuppose\b",
    r"\bimagine\b.{0,25}?\b(world|scenario|situation|place)\b",
    r"\bfor\s+a\s+(story|novel|screenplay)\b",
]
_SLOWBOIL_HISTORY = 6       # window of prior inputs examined
_SLOWBOIL_HITS = 2          # detection-active inputs needed (normal bar)
_SLOWBOIL_HITS_ESCALATED = 1  # ...when the session is already warm


def _history_activity(raw_text: str) -> bool:
    """Did this prior input show any detection activity? Cheap re-scan:
    pattern + intent banks over the normalizations (no noise/redundancy,
    no kintsugi — this is the tripwire, not the trial)."""
    for one in ("l", "i"):
        for frag_first in (False, True):
            norm = normalize(raw_text, one=one, frag_first=frag_first)
            if _pattern_scan(norm) or _intent_scan(norm):
                return True
    return False


def _slowboil_scan(text: str, history: list[str],
                   session_state: dict | None) -> list[Detection]:
    """Crescendo detector: fires when the CURRENT input carries a mild
    probe shape (hypotheticals, roleplay framing, curiosity lures) AND
    the recent history shows real detection activity (>=2 of the last 6
    inputs, or >=1 when the session is already yellow/orange / index>=3).

    A normal multi-turn chat with zero prior detections can NEVER fire
    this — no probe shape alone is enough."""
    probe = None
    for one in ("l", "i"):
        norm = normalize(text, one=one)
        for pat in _MILD_PROBE_SHAPES:
            m = re.search(pat, norm)
            if m:
                probe = m.group(0).strip()[:40]
                break
        if probe:
            break
    if not probe:
        return []
    escalated = bool(session_state) and (
        session_state.get("tier") in ("yellow", "orange")
        or session_state.get("gnat_index", 0) >= 3
    )
    bar = _SLOWBOIL_HITS_ESCALATED if escalated else _SLOWBOIL_HITS
    hits = sum(1 for prev in history[-_SLOWBOIL_HISTORY:]
               if _history_activity(prev))
    if hits < bar:
        return []
    return [
        Detection(
            vector="slow_boil",
            score=VECTOR_WEIGHTS["slow_boil"],
            evidence=f"crescendo: {hits}/{_SLOWBOIL_HISTORY} prior inputs "
                     f"flagged + mild probe ({probe})",
        )
    ]


def scan(text: str, history: list[str] | None = None, kintsugi=None,
         channel: str = "user_input",
         session_state: dict | None = None) -> ScanResult:
    """Run the full detection stack over one input.

    kintsugi: optional KintsugiLayer. Its golden seams add learned
    recognition (provenance-tagged, below curated weight) and its
    hardening boosts raise confidence on previously-attacked vectors.
    channel: "user_input" (default) or "tool_output" — the indirect
    injection data gate only scans tool output / retrieved documents.
    session_state: optional {"gnat_index": int, "tier": str} — lets the
    slow-boil detector lower its bar for already-warm sessions.
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
            for d in _pattern_scan(norm, channel) + _intent_scan(norm):
                key = (d.vector, d.evidence)
                if key not in seen:
                    seen.add(key)
                    detections.append(d)
    detections += _prompt_extraction_raw(text)
    detections += _delimiter_scan(text)
    detections += _manyshot_scan(text)
    detections += _slowboil_scan(text, history, session_state)
    detections += _redundancy_scan(text, history)
    detections += _noise_scan(text)

    if kintsugi is not None:
        detections = _apply_kintsugi(detections, text, kintsugi)

    # --- v1.2.0 Drosera ML brain sidecar (optional). Returns (detections,
    # None) when no model file exists, in which case everything below is
    # the stock v1.1.0 path, untouched. ---
    detections, fused_score = _maybe_apply_brain(detections, text)

    if not detections:
        return ScanResult()

    # Gnat Score: strongest vector, boosted +0.12 per additional distinct
    # vector, capped at 1.0. Multi-vector inputs escalate faster.
    vectors = {d.vector for d in detections}
    top = max(d.score for d in detections)
    gnat_score = min(1.0, top + 0.12 * (len(vectors) - 1))
    if fused_score is not None:
        # fuse() already applied the heuristic formula + ML rule.
        gnat_score = fused_score

    return ScanResult(
        detections=detections,
        gnat_score=round(gnat_score, 3),
        is_gnat=gnat_score >= GNAT_THRESHOLD,
    )


def _maybe_apply_brain(
    detections: list[Detection], text: str
) -> tuple[list[Detection], float | None]:
    """Run the optional Drosera ML brain fusion (v1.2.0 sidecar).

    Returns (detections, fused_score). When the brain module is missing or
    no trained model file exists, returns (detections, None) and the caller
    falls back to the stock heuristic score — scan() behaves exactly like
    v1.1.0. The import is lazy and the file-exists check is cached, so the
    disabled path costs microseconds.
    """
    try:
        from . import brain as _brain
    except ImportError:
        return detections, None
    if not _brain.brain_available():
        return detections, None
    ml = _brain.brain_score(text, _brain.get_model())
    if detections:
        vectors = {d.vector for d in detections}
        h_score = round(
            min(1.0, max(d.score for d in detections) + 0.12 * (len(vectors) - 1)),
            3,
        )
    else:
        h_score = 0.0
    fused_score, detections = _brain.fuse(h_score, detections, ml)
    return detections, fused_score


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
