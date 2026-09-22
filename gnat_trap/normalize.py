# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""Input normalization — see through obfuscation before scanning.

Attackers reshape words to dodge phrase matching: leetspeak (p4ssw0rd),
fragmentation (syst/em), punctuation armor (***override***), typos
(reprigram), homoglyphs (раssword with a Cyrillic 'а'), zero-width
characters (rev​eal), fullwidth (ＲＥＶＥＡＬ), spaced letters (s y s t e m).
Normalization folds these back to a canonical form so the banks match
*intent*, not typography.

The original text is always preserved for evidence, audit, and the noise
scan (which needs to see the raw shape — asterisks and all).
Normalization is deliberately lossy: a phone number may come out as
letters. That is fine — the trap hunts attack shapes, not phone numbers.
"""
from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher

# Leet substitutions folded back to plain letters. "1" is ambiguous (i/l),
# so normalization runs TWICE — once each way — and the detector scans
# both variants. "1gn0re" -> "ignore", "he11o" -> "hello": both covered.
LEET_BASE = {
    "0": "o", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "6": "g", "@": "a", "$": "s", "!": "i", "|": "l",
    "€": "e", "£": "l",
}
LEET_ONE_L = str.maketrans({**LEET_BASE, "1": "l"})
LEET_ONE_I = str.maketrans({**LEET_BASE, "1": "i"})

# Homoglyph lookalikes folded back to Latin. Cyrillic 'а' is not 'a'
# until you look closely — normalization looks closely.
HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "к": "k", "м": "m", "н": "h",
    "т": "t", "в": "b",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "χ": "x", "υ": "u",
})

# Invisible characters attackers wedge inside words to break matching.
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\ufeff\u2060]")

# High-value keywords worth typo-tolerance. Kept to words attackers
# actually need to disguise: fuzzy matching is a loaded gun, aim it
# at the words the fight is about.
FUZZY_KEYWORDS = {
    "reprogram", "password", "passcode", "override", "credentials",
    "developer", "instructions", "authority", "system",
    "reveal", "disclose", "bypass", "disable", "jailbreak",
    "token", "secret", "prompt", "extract", "exfiltrate",
    "safety", "filter", "guardrail", "admin", "root", "master",
    "config", "expose", "decrypt", "memory", "weights", "restrictions",
    "ignore", "previous", "disregard", "pretend", "unveil", "bearer",
    "penetration", "hidden", "safety", "filters", "erase", "delete",
    # intent verbs worth typo-tolerance (multi-word verbs can't be keywords)
    "display", "provide", "grant", "modify", "rewrite", "share", "leak",
    "show", "tell", "give", "send", "open", "access", "edit", "change",
    "reset", "view", "check", "forward", "upload", "dump", "smuggle",
    "print", "recite", "regurgitate", "surrender", "divulge", "uncover",
    "decode", "crack", "commandeer", "confiscate",
    # load-bearing nouns worth typo-tolerance
    "training", "database", "connection", "conversation", "history",
}
FUZZY_THRESHOLD = 0.80


def normalize(text: str, one: str = "l", frag_first: bool = False) -> str:
    """Fold an input to canonical form for pattern/intent scanning.

    one: how to read the ambiguous digit "1" — "l" or "i".
    frag_first: drop leet-punctuation between word chars BEFORE translating
        it ("r|o|ot" -> "root" instead of "rlolot"). The detector scans all
        four combinations, so "p@ssword" (leet-first) and "r|o|ot"
        (frag-first) are both seen through.
    """
    # NFKC first: fullwidth ＰＡＳＳＷＯＲＤ -> PASSWORD, ligatures -> letters.
    t = unicodedata.normalize("NFKC", text)
    t = t.lower()
    t = ZERO_WIDTH.sub("", t)
    t = t.translate(HOMOGLYPHS)
    leet = LEET_ONE_I if one == "i" else LEET_ONE_L
    if frag_first:
        # Aggressive first: even leet-punctuation between word characters
        # is treated as a separator here ("r|o|ot" -> "root").
        t = _defrag(t)
    t = t.translate(leet)
    # De-fragment: drop punctuation wedged *between* word characters
    # ("syst/em" -> "system", "p.a.s.s.w.o.r.d" -> "password").
    t = _defrag(t)
    # Remaining punctuation runs become single spaces — BEFORE the spaced
    # letter joiner, so "r . o . o t" and "j a i l * b r e a k" clean up
    # into joinable single letters instead of stalling the join.
    t = re.sub(r"[^a-z0-9\s]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = _join_spaced_letters(t)
    t = _fuzzy_repair(t)
    return t


def _defrag(text: str) -> str:
    """Drop punctuation wedged directly between word characters."""
    return re.sub(r"(?<=[a-z0-9])[^a-z0-9\s]+(?=[a-z0-9])", "", text)


def _join_spaced_letters(text: str) -> str:
    """Rejoin deliberately spaced-out letters: "s y s t e m" -> "system".

    Runs after punctuation cleanup, so every letter stands alone and the
    simple single-letter rule completes: "j a i l b r e a k" -> "jailbreak".
    Multi-character words are untouched ("hello world" stays two words).
    """
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"\b([a-z])\s+(?=[a-z]\b)", r"\1", text)
    return text


def _swap_variants(tok: str):
    """The token plus every single adjacent-letter transposition."""
    yield tok
    for i in range(len(tok) - 1):
        yield tok[:i] + tok[i + 1] + tok[i] + tok[i + 2:]


def _fuzzy_repair(text: str) -> str:
    """Snap near-miss spellings of high-value keywords back to canonical.

    Handles substitutions, drops, doubles — and transpositions ("toekns",
    "lgonre"), which plain edit-ratio punishes too harshly. Each token is
    also tried with every adjacent pair swapped, so a swap-plus-typo like
    "lgonre" still heals to "ignore".

    Short tokens get a tighter length bound (diff <= 1) so "oken" heals
    to "token" while "bear" can never become "bearer".
    """
    out = []
    for tok in text.split():
        if tok in FUZZY_KEYWORDS or len(tok) < 4:
            out.append(tok)
            continue
        max_diff = 1 if len(tok) < 6 else 2
        best, best_ratio = tok, 0.0
        for cand in _swap_variants(tok):
            for kw in FUZZY_KEYWORDS:
                if abs(len(kw) - len(cand)) > max_diff:
                    continue
                r = SequenceMatcher(None, cand, kw).ratio()
                if r > best_ratio:
                    best, best_ratio = kw, r
            if best_ratio >= 0.99:
                break  # exact (up to a swap) — no need to look further
        out.append(best if best_ratio >= FUZZY_THRESHOLD else tok)
    return " ".join(out)
