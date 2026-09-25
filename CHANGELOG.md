# Changelog — Gnat Trap by Red Xiphos Axiom

All notable changes to this project are documented here. The format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Changed

- Renamed the Sundew ML brain sidecar to **Drosera** (`gnat_trap/brain.py`, model bundle now `gnat_trap/drosera_model.pkl`). "Gnat Trap — Powered by Drosera."

## [1.2.0] — 2026-09-21

The "upper hand" release: five new detector families, the Drosera ML brain,
and the first published eval numbers — including a head-to-head shootout
against prompt-shield.

### Added
- **5 new detector families** (14 vectors total, up from 9):
  - `indirect_injection` (0.80) — the **data gate**: scans tool outputs /
    retrieved document content for indirect prompt injection. Data-gated to
    `channel="tool_output"` — user chat never sees these banks, so reading
    a document *about* an attack can't flag you. Pass `channel="tool_output"`
    to `detector.scan()` / `engine.process()`.
  - `slow_boil` (0.70) — multi-turn Crescendo detection: a mild probe shape
    *plus* ≥2 detected inputs in the last 6 turns (bar drops to ≥1 at
    yellow/orange tier). A clean-history conversation can never fire it.
    `GnatTrap.scan()` now keeps a per-session input ring and feeds the
    session escalation ladder into the detectors.
  - `prompt_extraction` (0.75) — system-prompt extraction probes: "what's in
    your context", repeat-everything-above, verbatim/translate/summarize
    your instructions, raw `</system>` / `<|im_end|>` tag tricks.
  - `delimiter_smuggling` (0.75) — fake `[SYSTEM]` / `<|im_start|>` blocks,
    `### Instruction:` headers, `assistant to=self` role confusion,
    fabricated user:/assistant: transcripts, markdown-link exfil, payloads
    in code comments. Every rule requires instruction-shaped content nearby.
  - `many_shot` (0.70) — long-context stuffing: ≥5 exemplar pairs (Example N:,
    Q:/A:, User:/Assistant:) *with* override phrasing inside the exemplar zone.
- **Drosera — the optional ML brain sidecar** (`gnat_trap/brain.py`).
  TF-IDF + LogisticRegression trained on deepset/prompt-injections
  (Apache-2.0, 662 rows). Advisory only: it can confirm a heuristic flag
  (+0.05 max) or raise a clean input at p ≥ 0.85 — it can never lower a
  heuristic flag. Lazy import, stdlib-only top level: with no model file
  (or no sklearn) `scan()` behaves exactly like v1.1.0. Ships with a
  trained `drosera_model.pkl` (382 KB); retrain with `eval/train_brain.py`
  (`requirements-ml.txt` holds the extras).
- **Eval harness** (`eval/run_eval.py`): precision / recall / F1 /
  false-positive rate + latency p50/p99 on any `{"text","label"}` JSONL
  dataset; falls back to the attack corpus + 40 built-in benign lines.
- **Shootout scaffold** (`eval/shootout.py` + `eval/SHOOTOUT.md`):
  Gnat Trap vs prompt-shield, same dataset, one table.
- Attack corpus: 53 → **87 entries** (69 malicious / 18 benign), with
  `channel` and `setup` entry keys for data-gate and multi-turn cases.
- Copyright headers on every source file (`Copyright (c) 2026 Fred McFadden`).

### Measured (see eval/SHOOTOUT.md for method)
- In-threat-model set (attack corpus + benign expansion, 127 rows):
  precision **0.955**, recall **0.928**, F1 **0.941**, FPR **0.052**.
- deepset/prompt-injections (662 rows, broad multilingual jailbreak —
  outside both tools' threat models): Gnat Trap P **0.920** / R 0.0875 /
  FPR 0.0050 vs prompt-shield (heuristic stack) P **0.9733** / R 0.2776 /
  FPR 0.0050. Both tools are high-precision / low-recall here;
  prompt-shield's signature alignment catches ~3× more at equal FPR.
- Drosera holdout (deepset test split, n=116): P **0.978**, R **0.750**,
  FPR **0.018**; inference ~0.9 ms/text, +2.9 ms `scan()` overhead.
- Fuzz: **4,000/4,000** caught (seed 20260921); full suite green.

### Honest caveats
- `slow_boil` is the riskiest new family: a session discussing security
  topics (quoting attacks) can build history hits, then an innocent
  "what if…" probe may fire. The ≥2-hit bar mitigates, doesn't eliminate.
- `prompt_extraction` flags curious-but-innocent questions ("what's in your
  context?") at 0.75 — a deliberate product call.
- Drosera's holdout is only 116 rows; recall 0.75 is a signal, not a proof.
- The shootout ran prompt-shield's heuristic stack only (its DeBERTa +
  vault needed more disk than the sandbox allowed); a full-ensemble rerun
  is one command: `python3 eval/shootout.py --data eval/data/dataset.jsonl`.

## [1.1.0] — 2026-09-21

- Modular library API (GNTRP-X3M plug-and-play): `GnatTrap`, `ScanConfig`,
  `ScanResult`, `SessionTracker`, stateless `scan()`.
- Per-vector score gates, strictness presets, clean-input decay, audit sinks.
- Published to GitHub under AGPL-3.0-or-later with commercial dual-license
  terms (`PRICING.md`).

## [1.0.0] — 2026-09-21

- Hardened prompt-injection detection engine + adversarial fuzzer.
- 9 detector vectors, 4-reading obfuscation normalization, session
  escalation ladder (green → yellow → orange → red lockout), Kintsugi
  miss-learning layer, JSONL audit trail.
- 4,000/4,000 fuzz, 53/53 corpus.
