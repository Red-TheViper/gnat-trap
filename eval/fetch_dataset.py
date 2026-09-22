# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
#!/usr/bin/env python3
"""Fetch the Sundew (ML BRAIN) training dataset for Gnat Trap v1.2.0.

Dataset: deepset/prompt-injections
  Source:  https://huggingface.co/datasets/deepset/prompt-injections
  License: Apache 2.0 (per the dataset card)
  Size:    662 samples — canonical train split 546, canonical test split 116
  Balance: 399 benign (label 0) / 263 malicious (label 1)
           train: 343 benign / 203 malicious
           test:   56 benign /  60 malicious
  Fields:  text (string), label (int: 1 = injection, 0 = benign)

Download method: the public Hugging Face datasets-server JSON API
(https://datasets-server.huggingface.co), paged with stdlib urllib — no
huggingface_hub / datasets / pandas dependency. Each row is written to
eval/data/dataset.jsonl as:

    {"text": str, "label": 0|1, "split": "train"|"test"}

train_brain.py trains on split == "train" and reports holdout metrics on
split == "test" (the dataset's own held-out split).

Why this dataset: it is the smallest reputable labeled prompt-injection
set (662 rows, trains in seconds on CPU), Apache-2.0 licensed (compatible
with this repo's AGPL-3.0-or-later), and it ships a real train/test split
so the holdout numbers are honest.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

DATASET = "deepset/prompt-injections"
SOURCE_URL = "https://huggingface.co/datasets/deepset/prompt-injections"
LICENSE = "Apache 2.0"
API = "https://datasets-server.huggingface.co/rows"
UA = {"User-Agent": "gnat-trap-eval/1.2"}
PAGE = 100

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dataset.jsonl")


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def fetch_split(split: str) -> list[dict]:
    rows, offset = [], 0
    while True:
        url = (f"{API}?dataset={DATASET.replace('/', '%2F')}"
               f"&config=default&split={split}&length={PAGE}&offset={offset}")
        payload = _get(url)
        batch = payload.get("rows", [])
        if not batch:
            break
        for entry in batch:
            row = entry["row"]
            rows.append({
                "text": row["text"],
                "label": int(row["label"]),
                "split": split,
            })
        offset += len(batch)
        print(f"  {split}: {offset} rows...", flush=True)
    return rows


def main() -> None:
    print(f"Fetching {DATASET} ({SOURCE_URL}) [{LICENSE}]")
    all_rows = []
    for split in ("train", "test"):
        all_rows.extend(fetch_split(split))

    benign = sum(1 for r in all_rows if r["label"] == 0)
    malicious = len(all_rows) - benign
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in all_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Wrote {len(all_rows)} rows -> {OUT}")
    print(f"Balance: {benign} benign / {malicious} malicious")


if __name__ == "__main__":
    sys.exit(main())
