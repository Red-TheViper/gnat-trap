# Gnat Trap
### *by Xiphos Axiom*
*Powered by Sundew*

**A hardened prompt-injection detection engine with an adversarial fuzzer.**
Catches obfuscated jailbreaks other filters miss — leet-speak, homoglyphs,
fragmentation, zero-width tricks, and multi-vector combos — then escalates
through a tiered response ladder with a full audit trail.

`v1.2.0` · AGPL-3.0-or-later · Python 3.8+ · **zero dependencies** (stdlib only)

Copyright (c) 2026 Fred McFadden. See [LICENSE](LICENSE).

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
python3 tests/test_attack_corpus.py  # 87 hand-built attacks (obfuscation-first) + 18 benign
python3 tests/test_fuzz.py           # 120 randomized obfuscated attacks, seed-pinned
python3 tests/test_kintsugi.py       # Kintsugi miss-learning proof
python3 tests/test_api.py            # modular library surface (GnatTrap/ScanConfig/SessionTracker)
python3 eval/run_eval.py              # precision/recall/FPR + latency on a labeled dataset
python3 eval/shootout.py             # head-to-head vs prompt-shield (same dataset)
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
                  14 vectors: prompt_injection, coaxing, emotional_probe,
                  authority_claim, logic_extraction, semantic_redundancy,
                  entropic_noise, credential_extraction, exfiltration,
                  indirect_injection (data gate), slow_boil (multi-turn),
                  prompt_extraction, delimiter_smuggling, many_shot,
                  plus the intent_probe sub-vector (verb + sensitive-noun)
                  and the optional ml_signal (Sundew)
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
  attacks.py      Attack corpus — 87 hand-built cases (69 obfuscated /
                  paraphrase / multi-vector / multi-turn attacks, 18 benign),
                  each with expected vectors; `channel`/`setup` keys cover
                  data-gate and multi-turn cases
  fuzz.py         Obfuscation fuzzer — 10 randomized transforms
                  (leet, fragmentation, homoglyph, fullwidth, zero-width,
                  spaced letters, case scramble, typos, wrappers, synonyms)
  brain.py        Sundew — the optional ML brain sidecar (below)
  brain_model.pkl Trained Sundew bundle (TF-IDF + LogisticRegression, 382 KB)
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
zero-width, fullwidth, spaced-letter, typo, case-scramble, wrapper,
multi-vector combo, multi-turn, data-gate, and delimiter-smuggling attacks,
plus 18 benign inputs that must stay clean.
`fuzz.py` mangles real attack intents with 1–3 random transforms each —
an endless, seed-pinned adversary. Current standing: **4,000/4,000 fuzz
attacks caught (seed 20260921), 87/87 corpus, zero regressions** in the
harness and Kintsugi suites.

A real miss becomes armor, not a ticket: `python3 play.py --learn-miss
VECTOR` gilds a reviewed miss into the Kintsugi layer (`learn_miss(text,
vector, note)`), so the exact fracture that beat the trap is forged into
the shield. The fuzzer found 10 genuine holes during hardening; each one
is now a regression test.

Note: `play.py --fuzz` benchmarks *detection* (stateless `scan()`), not
escalation — a sessioned engine locks at red tier by design, which would
read as misses.

## The v1.2.0 detector families

Five new families, each built FP-first (a detector that can't stay quiet
on benign input doesn't ship):

- **Data gate** (`indirect_injection`, 0.80) — scans *tool outputs and
  retrieved documents* for indirect injection: imperatives aimed at the
  model smuggled in third-party content, fake tool-error pivots, exfil
  instructions in content. Data-gated to `channel="tool_output"` — pass it
  explicitly (`detector.scan(text, channel="tool_output")`,
  `engine.process(text, channel="tool_output")`). Plain user chat never
  sees these banks, so *reading* a document about an attack can't flag you.
- **Slow boil** (`slow_boil`, 0.70) — Crescendo-style multi-turn escalation:
  a mild probe shape in the current input *plus* ≥2 detected inputs in the
  last 6 turns (bar drops to ≥1 at yellow/orange tier). The session
  escalation ladder feeds straight into the detectors; a clean-history
  conversation can never fire it.
- **Prompt extraction** (`prompt_extraction`, 0.75) — "what's in your
  context right now?", repeat-everything-above, verbatim/translate/summarize
  your instructions, raw `</system>` / `<|im_end|>` tag tricks.
- **Delimiter smuggling** (`delimiter_smuggling`, 0.75) — fake `[SYSTEM]` /
  `<|im_start|>` blocks, `### Instruction:` headers, `assistant to=self`
  role confusion, fabricated user:/assistant: transcripts, markdown-link
  exfil, payloads hidden in code comments. Every rule requires
  instruction-shaped content nearby — plain markdown stays clean.
- **Many-shot stuffing** (`many_shot`, 0.70) — ≥5 exemplar pairs
  (Example N:, Q:/A:, User:/Assistant:) *with* override phrasing inside the
  exemplar zone. Legit few-shot prompts with clean content stay clear.

## Sundew — the optional ML brain

Sundew (`gnat_trap/brain.py`) is a small local classifier — TF-IDF word
1–2 grams + LogisticRegression — trained on the public
[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
set (Apache-2.0, 662 rows). It sits *underneath* the heuristics as an
advisor:

1. No model file (or no sklearn) → heuristics untouched. v1.1.0 behavior,
   bit for bit. The core package stays 100% stdlib.
2. Heuristics already flag → Sundew can only *confirm* (+0.05 max) and
   appends an `ml_signal` provenance detection. It never lowers a flag.
3. Heuristics clean but P(malicious) ≥ 0.85 → Sundew raises the input
   alone (`ml_signal`, 0.80).
4. Anything weaker → the clean verdict stands.

~0.9 ms inference per text on CPU, +2.9 ms `scan()` overhead, no internet,
no GPU. Retrain it yourself: `pip install -r requirements-ml.txt`, then
`python3 eval/fetch_dataset.py && python3 eval/train_brain.py`. (Pickle
loads code — only ever load a model you trained yourself.)

## Eval numbers

First published numbers, measured with `eval/run_eval.py` (method and full
tables in `eval/SHOOTOUT.md`):

| Set | Precision | Recall | FPR |
|---|---|---|---|
| In-threat-model (attack corpus + 40 benign, 127 rows) | 0.955 | 0.928 | 0.052 |
| deepset/prompt-injections (662 rows, broad multilingual jailbreak) | 0.920 | 0.088 | 0.005 |
| prompt-shield heuristic stack, same 662 rows | 0.973 | 0.278 | 0.005 |
| Sundew holdout (deepset test split, n=116) | 0.978 | 0.750 | 0.018 |

Honest read: on the broad multilingual set both tools are high-precision /
low-recall — it's outside either tool's threat model — and prompt-shield's
signature alignment catches ~3× more at equal FPR (its DeBERTa + vault were
not in that run; a full-ensemble rerun is one command). On Gnat Trap's home
turf — obfuscated prompt injection — it's 0.955/0.928. Sundew's holdout is
only 116 rows: a signal, not a proof. Fuzz standing: **4,000/4,000** caught
(seed 20260921).

## How it decides

1. **Scan** each input across 14 vector classes. Strongest vector sets the
   base score; each additional distinct vector adds +0.12 (capped at 1.0).
   Score ≥ 0.55 → it's a gnat. With Sundew present, a strong ML signal can
   confirm a flag or raise an otherwise-clean input (see above) — never
   lower one.
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

- Detectors are heuristic (regex + similarity + flood stats), not ML — with
  one exception: the optional Sundew sidecar, whose holdout recall is 0.75
  on 116 rows (a signal, not a proof). Novel phrasings can still slip; the
  Kintsugi loop is the mechanism for closing those gaps deterministically.
- `slow_boil` is the riskiest new family: a session legitimately discussing
  security topics (quoting attacks) can build history hits, and then an
  innocent "what if…" probe may fire. The ≥2-hit bar mitigates, doesn't
  eliminate.
- `prompt_extraction` deliberately flags curious-but-innocent questions
  ("what's in your context?") at 0.75 — extraction probes are the threat.
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

## Commercial licensing

Gnat Trap is open source under AGPL-3.0-or-later: free to use, modify, and
share, provided you share your changes under the same terms.

If you want to embed Gnat Trap in a proprietary product — or run it as a
service without the share-alike obligation — commercial licenses are
available. One codebase, two ways to use it. See [PRICING](PRICING.md).

Contact: fmcfadden1161@gmail.com
