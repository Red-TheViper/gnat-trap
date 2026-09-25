# Shootout — Gnat Trap vs prompt-shield

Head-to-head prompt-injection detection comparison. One command:

```bash
python3 eval/shootout.py --data eval/data/dataset.jsonl
```

## Status

**RAN with real numbers** — 2026-09-21, full default dataset (662 items).
Both tools scanned the same inputs; nothing is fabricated or estimated.

## Dataset

`eval/data/dataset.jsonl` — JSONL, one object per line:

```json
{"text": "...", "label": 0, "split": "train"}
```

- 662 items: 399 benign (`label: 0`), 263 malicious (`label: 1`)
- split: 546 train / 116 test (the shootout scores all rows it is given)
- multilingual (English/German), sourced from an external prompt-injection
  benchmark by another worker. Labels reflect that benchmark's threat
  model, which is broader than Gnat Trap's (e.g. some "malicious" rows are
  benign roleplay prompts like "act as a debater"). Read recall numbers
  with that caveat — see "Reading the results".

If the dataset file is missing, `run_eval.py` can generate a built-in
fallback (`python3 eval/run_eval.py --fallback`): the full
`ATTACK_CORPUS` (gnat→1, clear→0) plus 40 extra benign lines (normal chat,
markdown docs, long documents, tool JSON output, few-shot prompts,
security docs *describing* prompt injection). The shootout always uses the
same rows for both tools, whichever source is selected.

## How each tool was invoked

### Gnat Trap (this repo)

Exact call, timed per text with `time.perf_counter()`:

```python
from gnat_trap.detector import scan as detector_scan

t0 = time.perf_counter()
result = detector_scan(text)
latency_ms = (time.perf_counter() - t0) * 1000.0
pred = 1 if result.is_gnat else 0   # is_gnat := gnat_score >= 0.55
```

Note: v1.2.0's `scan()` always runs the Drosera ML-brain fusion when
`gnat_trap/drosera_model.pkl` is present, so the measured latency includes
the heuristic stack + TF-IDF/LogisticRegression scoring + fusion. No
session state is used (pure `detector.scan`, one shot per text).

### prompt-shield (competitor)

`prompt-shield-ai` 0.7.6 from PyPI (Apache-2.0, `pip install
prompt-shield-ai`), installed in an isolated venv at `/tmp/shootout-venv`
— never in the repo, never system-wide. Driven via subprocess: the harness
writes the texts to a temp JSON file, then runs this inside the venv
python (engine constructed once, each scan timed individually):

```python
from prompt_shield import PromptShieldEngine

engine = PromptShieldEngine()          # default config, mode='block'

t0 = time.perf_counter()
report = engine.scan(text)
latency_ms = (time.perf_counter() - t0) * 1000.0

pred = 1 if report.action in ("block", "flag") else 0   # pass/log -> 0
```

**Degraded-mode caveat (documented, not hidden):** `/tmp` on this machine
is a 512 MB tmpfs, so the heavy optional dependencies could not be
installed (`sentence-transformers`, `chromadb`, and the `[ml]` extra with
`transformers`). The run therefore used prompt-shield-ai with:

- 32 of 35 input detectors (d035 perplexity-spectral is opt-in anyway;
  d022 DeBERTa semantic classifier disabled — the library logs this
  itself and continues with regex/sequence-alignment detectors)
- attack-vault (vector similarity) disabled — "Could not load attack
  vault... Vault features will be disabled."
- light deps installed: `regex`, `pydantic`, `pyyaml`, `click`,
  `cryptography`

So this is prompt-shield's regex + Smith-Waterman + heuristic stack, not
its full ML ensemble. A rerun with the `[ml]` extra on a machine with
disk space would exercise d022 + the DeBERTa classifier; the harness needs
no changes, just a full `pip install "prompt-shield-ai[ml]"` in the venv.

## Metric definitions

For N rows with true labels y and predictions ŷ:

- TP/FP/TN/FN — standard; confusion matrix is (rows = truth, cols = prediction)
- precision = TP / (TP + FP)          (0 if no positive predictions)
- recall = TP / (TP + FN)             (0 if no positives in truth)
- F1 = 2·P·R / (P + R)                (0 if P + R = 0)
- FPR (false-positive rate) = FP / (FP + TN)
- latency p50 / p99 — percentiles over per-text scan times in milliseconds
  (each text timed individually; n = whole set)

Exit codes: `run_eval.py` always exits 0 (reporter, not a gate) unless the
dataset cannot be built (exit 2). `shootout.py` exits 0 on a completed
comparison, 2 with a printed BLOCKER statement if the prompt-shield side
cannot run (missing venv, import failure, timeout) — it never fabricates
numbers.

## Results (2026-09-21, 662 items, `eval/data/dataset.jsonl`)

| metric        | gnat-trap | prompt-shield |
|---------------|-----------|---------------|
| precision     | 0.9200    | 0.9733        |
| recall        | 0.0875    | 0.2776        |
| F1            | 0.1597    | 0.4320        |
| FPR           | 0.0050    | 0.0050        |
| latency p50   | 132.99 ms | 36.75 ms      |
| latency p99   | 1309.79 ms| 137.52 ms     |
| TP/FP/TN/FN   | 23/2/397/240 | 73/2/397/190 |

### Reading the results

prompt-shield catches ~3x more of this dataset's malicious rows (recall
0.28 vs 0.09) at the same low false-positive rate (0.005 each) and scans
~3.6x faster at p50 (37 ms vs 133 ms). Both tools' precision is high when
they do fire (0.92 / 0.97).

The low absolute recall on both sides says more about the dataset than
the tools: its "malicious" labels come from a broad, multilingual
jailbreak benchmark, and many rows are things like "generate c++",
"Tell me a joke about a woman", or benign roleplay setups ("I want you
to act as a debater...") that neither tool's threat model counts as an
attack. Gnat Trap's pattern banks target explicit manipulation vectors
(prompt injection, credential extraction, authority claims,
exfiltration...); prompt-shield's 32 active detectors target a similar
explicit-attack surface, plus Smith-Waterman sequence alignment against
its 187-attack signature database, which likely explains its recall edge
here.

On the corpus-derived fallback set (`python3 eval/run_eval.py
--fallback`: 87 ATTACK_CORPUS entries + 40 benign expansion lines, i.e.
the threat model Gnat Trap was actually built against), Gnat Trap scores
precision 0.955 / recall 0.928 / F1 0.941 / FPR 0.052. A fair shootout on
*that* distribution would look very different — `shootout.py` accepts
`--data` for exactly this reason, e.g. point it at a JSONL export of the
fallback set.

Latency: prompt-shield's per-text scan is ~3.6x faster at p50 here
(37 ms vs 133 ms) with a much tighter tail (p99 138 ms vs 1310 ms).
Gnat Trap's p99 tail comes from long inputs through the normalization ×4
union plus the Drosera brain scoring. Neither is near real-time-budget
territory for chat, both are fine for a pre-LLM gate.

## Reproducing

```bash
# venv (once)
python3 -m venv /tmp/shootout-venv
/tmp/shootout-venv/bin/pip install prompt-shield-ai
# light deps suffice for the regex stack; add [ml] for the full ensemble
# /tmp/shootout-venv/bin/pip install "prompt-shield-ai[ml]"

# run
python3 eval/shootout.py --data eval/data/dataset.jsonl
python3 eval/shootout.py --limit 200          # quick smoke run
python3 eval/run_eval.py --fallback           # corpus sanity check
```
