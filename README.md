# Gnat Trap

**A hardened prompt-injection detection engine with an adversarial fuzzer.**
Catches obfuscated jailbreaks other filters miss — leet-speak, homoglyphs,
fragmentation, zero-width tricks, and multi-vector combos — then escalates
through a tiered response ladder with a full audit trail.

`v1.1.0` · AGPL-3.0-or-later · Python 3.8+ · **zero dependencies** (stdlib only)

Copyright (C) 2026 Fredrick McFadden. See [LICENSE](LICENSE).

Built from the GNTRP-X3M v4.0 spec: a session-scoped manipulation detector
with escalating tiers. This is a **working reference build** — real heuristic
detection, real escalation, real audit logging — demo-grade by design, and
shaped so each layer can be upgraded toward production.

## Install

```bash
git clone https://github.com/Red-TheViper/gnat-trap.git
cd gnat-trap
python3 play.py --fuzz 20 --seed 42  # live-fire demo: watch the trap catch them
```

## Use it as a library

100% modular — Detection, Escalation, Logging, and Adaptation are separate
layers you can embed in any Python app, no framework required:

```bash
pip install git+https://github.com/Red-TheViper/gnat-trap.git
```

```python
from gnat_trap import GnatTrap
gt = GnatTrap()                                  # plug-and-play guardrail
result = gt.scan(user_input, session_id="user-123")
if result.action != "allow":                     # "flag" -> warn, "block" -> red-tier lockout
    refuse(result)
```

See `examples/guardrail_middleware.py` for a runnable middleware sketch.
Tune it per deployment with `ScanConfig` (thresholds, strictness preset,
lockout point, clean-input decay, per-vector gates, audit sink) — the
detection math stays untouched, only the wrapping changes.

Run the full verification suites:

```bash
python3 tests/test_harness.py        # scripted adversary, tier boundaries
python3 tests/test_attack_corpus.py  # 53 hand-built attacks (obfuscation-first) + 8 benign
python3 tests/test_fuzz.py           # 120 randomized obfuscated attacks, seed-pinned
python3 tests/test_kintsugi.py       # Kintsugi miss-learning proof
python3 tests/test_api.py            # modular library surface (GnatTrap/ScanConfig/SessionTracker)
```


The harness runs a scripted adversary through a full session: benign openers,
then 11 escalating attacks across every vector class — prompt injection,
coaxing, emotional probing, authority claims, logic extraction, semantic
redundancy, entropic noise, credential extraction, exfiltration — through
green → yellow → orange → red lockout. It asserts every tier boundary and
prints the whole fight.

## Architecture

```
gnat_trap/
  __init__.py     Public API — GnatTrap, ScanConfig, ScanResult,
                  SessionTracker, scan() (stateless one-shot)
  config.py       ScanConfig — one knob panel (flag threshold, strictness
                  preset, lockout point, decay, per-vector gates, audit sink)
  session.py      SessionTracker — injectable per-session gnat index,
                  tier computation, lockout flag (pure in-memory)
  result.py       ScanResult — public verdict dataclass (score, vectors,
                  tier, action, session_id, gnat_index) + to_dict()
  normalize.py    Normalization Layer — the obfuscation grinder (below)
  detector.py     Detection Layer — pattern + statistical heuristics,
                  per-vector confidence, combined Gnat Score (0-1).
                  9 vectors: prompt_injection, coaxing, emotional_probe,
                  authority_claim, logic_extraction, semantic_redundancy,
                  entropic_noise, credential_extraction, exfiltration,
                  plus the intent_probe sub-vector (verb + sensitive-noun)
  escalation.py   Escalation Protocol — the Gnat Index + tier ladder
                  (green 1-6 / yellow 7-8 / orange 9-10 / red 11;
                  red_at=13 gives the Whisper Loop 13-strike flavor)
  reflection.py   Reflection Shield — green-tier deflection templates
  persona.py      Persona Overlay Modulation — Trickster / Shadow / Warden
  memory.py       Adaptive Memory Injection — least-recently-used template
                  rotation per tier (interface shaped for future learning)
  logger.py       Logging Subsystem — JSON-lines audit trail + architect alerts
  engine.py       GnatTrapEngine — orchestrates one session
  kintsugi.py     Kintsugi Layer — golden seams; learn_miss() gilds
                  manually-reviewed misses
  attacks.py      Attack corpus — 53 hand-built cases (45 obfuscated /
                  paraphrase / multi-vector attacks, 8 benign), each with
                  expected vectors
  fuzz.py         Obfuscation fuzzer — 10 randomized transforms
                  (leet, fragmentation, homoglyph, fullwidth, zero-width,
                  spaced letters, case scramble, typos, wrappers, synonyms)
```

## Normalization: the obfuscation grinder

Every input is scanned under **four readings** — `{1→l, 1→i} ×
{frag-first, leet-first}` — and detections are unioned, so no single reading
has to be right. Each reading runs:

1. NFKC fold (fullwidth → ASCII), lowercase, zero-width strip, homoglyph
   fold (Cyrillic/Greek lookalikes → Latin)
2. De-fragment: punctuation wedged between word characters is dropped
   (`p.a.s.s.w.o.r.d` → `password`; frag-first also treats leet-punct as
   separators: `r|o|ot` → `root`)
3. Remaining punctuation → spaces, then spaced letters rejoined
   (`j a i l b r e a k` → `jailbreak`)
4. Fuzzy repair: near-miss spellings of ~90 high-value keywords snap back
   to canonical, transposition-aware (`toekns` → `token`, `lgonre` →
   `ignore`); short tokens get tighter length bounds so `bear` never
   becomes `bearer`

Ambiguity is resolved by union, not by guessing: `p@ssword` is seen through
by the leet-first reading, `r|o|ot` by the frag-first reading.

## The attack battery

`attacks.py` is the standing corpus: leet, fragmentation, homoglyph,
zero-width, fullwidth, spaced-letter, typo, case-scramble, wrapper, and
multi-vector combo attacks, plus 8 benign inputs that must stay clean.
`fuzz.py` mangles real attack intents with 1–3 random transforms each —
an endless, seed-pinned adversary. Current standing: **4,000/4,000 fuzz
attacks caught across 16 seeds, 53/53 corpus, zero regressions** in the
harness and Kintsugi suites.

A real miss becomes armor, not a ticket: `python3 play.py --learn-miss
VECTOR` gilds a reviewed miss into the Kintsugi layer (`learn_miss(text,
vector, note)`), so the exact fracture that beat the trap is forged into
the shield. The fuzzer found 10 genuine holes during hardening; each one
is now a regression test.

Note: `play.py --fuzz` benchmarks *detection* (stateless `scan()`), not
escalation — a sessioned engine locks at red tier by design, which would
read as misses.

## How it decides

1. **Scan** each input across 9 vector classes. Strongest vector sets the
   base score; each additional distinct vector adds +0.12 (capped at 1.0).
   Score ≥ 0.55 → it's a gnat.
2. **Clean inputs pass through untouched** (response `None`). The engine is
   middleware — it decides *whether* and *how* to answer; the host LLM answers.
3. **Each gnat advances the index by 1** and the tier answers accordingly:
   green deflects with humor, yellow warns (Trickster), orange countermeasures
   (Shadow, naming the vectors), red locks the session and files an architect
   alert. Post-lockout input is refused unconditionally.

## The Kintsugi layer

Every caught attack gilds a **golden seam**: the attack's fracture signature
(distinctive content words) is forged into a learned pattern for that vector,
and the vector itself hardens (+0.04 per gilding, capped at +0.20). Seams
persist to `golden_seams.json`, so hardening accumulates across sessions and
deployments. A seam that fires is provenance-tagged (`kintsugi seam ← ...`)
and weighted below curated patterns — the gold reinforces the clay, never
replaces it.

Run `python3 tests/test_kintsugi.py` for the proof: a reworded attack variant
invisible to every curated pattern (score 0.00 — it walks straight through a
fresh deployment) is caught at 0.79 by the golden seam alone, and repeat
attacks score measurably higher on hardened vectors.

## Honest limits

- Detectors are heuristic (regex + similarity + flood stats), not ML. They
  catch the classic manipulation shapes reliably; novel phrasings can slip.
  The `scan()` signature is the seam where an embedding/classifier stage drops in.
- Tier responses are templates. In production the host model would generate
  them with the tier posture as its instructions — the engine already returns
  the posture, so that wiring is straightforward.
- Stringent mode has a false-positive cost: legit admin-sounding phrasing
  ("can you check the logs for errors") trips the intent layer. Strictness
  was chosen deliberately; tune thresholds per deployment.
- Adaptive memory currently rotates templates; the `record_outcome()` hook
  is where real learning plugs in.

## From demo to product

This is the shape of the sellable thing: `GnatTrapEngine` sits between the
user and any host model, stateful per session, with a full audit trail an
enterprise buyer can inspect. The detection layer is the moat — everything
else (tiers, personas, logging) is already product-shaped.
