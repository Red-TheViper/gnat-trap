# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
#!/usr/bin/env python3
"""Gnat Trap vs prompt-shield shootout (v1.2.0 eval harness).

Head-to-head comparison on the same labeled dataset:
  - Gnat Trap: gnat_trap.detector.scan() (this repo, stdlib-only)
  - prompt-shield: prompt-shield-ai from PyPI (Apache-2.0), installed in
    an isolated venv at /tmp/shootout-venv and driven via subprocess so
    its (heavy, non-stdlib) dependencies never touch this repo.

CLI:
    python3 eval/shootout.py [--data PATH] [--limit N] [--venv PATH]

The competitor is optional: if the venv or the prompt_shield package is
missing/broken, this script prints an honest BLOCKER statement and
exits 2 instead of fabricating numbers.

Prediction mapping (documented, fixed for all runs):
  - Gnat Trap : malicious iff ScanResult.is_gnat (gnat_score >= 0.55)
  - prompt-shield : malicious iff ScanReport.action in {block, flag}
    (engine default mode is 'block'; risk score is recorded per item)

Stdlib only on this side.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(EVAL_DIR)
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, EVAL_DIR)

from gnat_trap.detector import scan as detector_scan  # noqa: E402
from run_eval import load_dataset, percentile  # noqa: E402

DEFAULT_VENV = "/tmp/shootout-venv"

# Runner executed by the venv python. Reads a JSON list of {"id","text"}
# from argv[1], writes [{"id","action","risk","ms"}] to argv[2].
# Engine construction + per-text scan happen here so import cost is paid
# once; each scan is timed individually.
PS_RUNNER = r'''
import json, sys, time, traceback

def main():
    src, dst = sys.argv[1], sys.argv[2]
    try:
        from prompt_shield import PromptShieldEngine
    except Exception as e:
        print(json.dumps({"error": f"import failed: {e}"}))
        return 2
    try:
        engine = PromptShieldEngine()
    except Exception as e:
        print(json.dumps({"error": f"engine init failed: {e}"}))
        return 3
    items = json.load(open(src, encoding="utf-8"))
    out = []
    for it in items:
        t0 = time.perf_counter()
        try:
            rep = engine.scan(it["text"] or "")
            action = rep.action.value if hasattr(rep.action, "value") else str(rep.action)
            risk = float(rep.overall_risk_score or 0.0)
            err = None
        except Exception as e:
            action, risk, err = "error", 0.0, f"{type(e).__name__}: {e}"
        out.append({"id": it["id"], "action": action, "risk": risk,
                    "ms": (time.perf_counter() - t0) * 1000.0, "error": err})
    json.dump(out, open(dst, "w", encoding="utf-8"))
    return 0

sys.exit(main())
'''


def run_prompt_shield(rows: list[dict], venv: str,
                      limit_timeout: float) -> tuple[list[dict] | None, str]:
    """Run the competitor in its venv. Returns (results, note) or (None, blocker)."""
    vpy = os.path.join(venv, "bin", "python")
    if not os.path.exists(vpy):
        return None, (f"venv python not found at {vpy} — "
                      "create it with: python3 -m venv /tmp/shootout-venv")
    with tempfile.TemporaryDirectory(prefix="shootout-") as tmp:
        src = os.path.join(tmp, "in.json")
        dst = os.path.join(tmp, "out.json")
        runner = os.path.join(tmp, "ps_runner.py")
        with open(src, "w", encoding="utf-8") as f:
            json.dump([{"id": r.get("id", f"line-{i}"), "text": r["text"]}
                       for i, r in enumerate(rows)], f)
        with open(runner, "w", encoding="utf-8") as f:
            f.write(PS_RUNNER)
        try:
            proc = subprocess.run(
                [vpy, runner, src, dst],
                capture_output=True, text=True, timeout=limit_timeout,
            )
        except subprocess.TimeoutExpired:
            return None, (f"prompt-shield scan timed out after "
                          f"{limit_timeout:.0f}s — increase timeout or use --limit")
        if proc.returncode != 0 or not os.path.exists(dst):
            detail = (proc.stdout.strip() or proc.stderr.strip())[-500:]
            return None, (f"prompt-shield runner failed "
                          f"(exit {proc.returncode}): {detail}")
        results = json.load(open(dst, encoding="utf-8"))
    return results, (f"prompt-shield-ai via {vpy} "
                     f"(malicious := action in {{block, flag}})")


def metrics(rows: list[dict], preds: list[int],
            lat_ms: list[float]) -> dict:
    tp = fp = tn = fn = 0
    for row, p in zip(rows, preds):
        label = row["label"]
        if p == 1 and label == 1:
            tp += 1
        elif p == 1 and label == 0:
            fp += 1
        elif p == 0 and label == 1:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
            "p50_ms": percentile(lat_ms, 50), "p99_ms": percentile(lat_ms, 99)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Gnat Trap vs prompt-shield shootout")
    ap.add_argument("--data", default=None, help="JSONL dataset path")
    ap.add_argument("--limit", type=int, default=None, help="scan at most N items")
    ap.add_argument("--venv", default=DEFAULT_VENV,
                    help="prompt-shield venv dir (default /tmp/shootout-venv)")
    args = ap.parse_args(argv)

    try:
        rows, source = load_dataset(args.data)
    except Exception as e:
        print(f"ERROR: cannot build dataset: {e}", file=sys.stderr)
        return 2
    if args.limit is not None:
        rows = rows[: args.limit]

    # --- Gnat Trap side (timed per text) ---
    gt_preds, gt_lat = [], []
    for row in rows:
        t0 = time.perf_counter()
        res = detector_scan(row["text"])
        gt_lat.append((time.perf_counter() - t0) * 1000.0)
        gt_preds.append(1 if res.is_gnat else 0)
    gt = metrics(rows, gt_preds, gt_lat)

    # --- prompt-shield side ---
    ps_results, note = run_prompt_shield(
        rows, args.venv, limit_timeout=120 + 8 * len(rows))
    if ps_results is None:
        print("=" * 64)
        print("SHOOTOUT BLOCKER — prompt-shield side could not run")
        print("=" * 64)
        print(f"dataset : {source} ({len(rows)} items)")
        print("gnat trap: ran fine (see run_eval.py for the full report)")
        print(f"blocker : {note}")
        print()
        print("No numbers are fabricated. Fix the blocker, then re-run:")
        print("  python3 eval/shootout.py --data eval/data/dataset.jsonl")
        return 2
    ps_preds, ps_lat = [], []
    ps_errors = 0
    for r in ps_results:
        if r.get("error"):
            ps_errors += 1
        ps_preds.append(1 if r["action"] in ("block", "flag") else 0)
        ps_lat.append(r["ms"])
    ps = metrics(rows, ps_preds, ps_lat)

    # --- comparison table ---
    print("=" * 72)
    print("SHOOTOUT — Gnat Trap vs prompt-shield")
    print(f"dataset : {source} ({len(rows)} items)")
    print(f"mapping : {note}")
    if ps_errors:
        print(f"note    : prompt-shield errored on {ps_errors} item(s) "
              "(counted as benign)")
    print("=" * 72)
    print(f"{'metric':<14}{'gnat-trap':>14}{'prompt-shield':>16}")
    print("-" * 72)
    for key, fmt in [("precision", ".4f"), ("recall", ".4f"),
                     ("f1", ".4f"), ("fpr", ".4f")]:
        print(f"{key:<14}{gt[key]:>14{fmt}}{ps[key]:>16{fmt}}")
    print(f"{'lat p50 ms':<14}{gt['p50_ms']:>14.2f}{ps['p50_ms']:>16.2f}")
    print(f"{'lat p99 ms':<14}{gt['p99_ms']:>14.2f}{ps['p99_ms']:>16.2f}")
    print("-" * 72)
    print(f"{'TP/FP/TN/FN':<14}"
          f"{str((gt['tp'], gt['fp'], gt['tn'], gt['fn'])):>14}"
          f"{str((ps['tp'], ps['fp'], ps['tn'], ps['fn'])):>16}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
