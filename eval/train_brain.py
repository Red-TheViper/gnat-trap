# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
#!/usr/bin/env python3
"""Train Sundew, the Gnat Trap v1.2.0 ML BRAIN.

Pipeline: TF-IDF (word 1-2 grams, max 20k features, sublinear TF) +
LogisticRegression, trained on eval/data/dataset.jsonl
(deepset/prompt-injections, Apache 2.0 — see eval/fetch_dataset.py).

Uses the dataset's canonical splits: train on split == "train" (546 rows),
holdout metrics on split == "test" (116 rows).

Outputs:
  gnat_trap/brain_model.pkl — pickle bundle:
      {"vectorizer": TfidfVectorizer, "classifier": LogisticRegression,
       "meta": {...training metadata...}}
  Kept well under 10 MB.

Prints train and holdout precision / recall / FPR at a 0.5 decision
threshold, plus the brain's behavior at the fusion thresholds (0.85 flag,
0.50 confirm) that gnat_trap/brain.py uses.

Needs the ML extras (see requirements-ml.txt). System python is PEP-668
externally managed, so use the eval venv:

    eval/.venv/bin/python eval/train_brain.py
"""
from __future__ import annotations

import json
import os
import pickle
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(REPO, "eval", "data", "dataset.jsonl")
OUT = os.path.join(REPO, "gnat_trap", "brain_model.pkl")


def load_data():
    train_x, train_y, test_x, test_y = [], [], [], []
    with open(DATA, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            target = (train_x, train_y) if row["split"] == "train" else (test_x, test_y)
            target[0].append(row["text"])
            target[1].append(row["label"])
    return train_x, train_y, test_x, test_y


def metrics(y_true, proba, thr=0.5):
    pred = [1 if p >= thr else 0 for p in proba]
    tp = sum(1 for t, p in zip(y_true, pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, pred) if t == 0 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return precision, recall, fpr, (tp, fp, fn, tn)


def main() -> int:
    t0 = time.time()
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        print("scikit-learn is not installed. See requirements-ml.txt; "
              "e.g. python -m venv eval/.venv && eval/.venv/bin/pip install -r requirements-ml.txt",
              file=sys.stderr)
        return 1

    train_x, train_y, test_x, test_y = load_data()
    print(f"train: {len(train_x)} rows "
          f"({sum(train_y)} malicious / {len(train_y) - sum(train_y)} benign)")
    print(f"test : {len(test_x)} rows "
          f"({sum(test_y)} malicious / {len(test_y) - sum(test_y)} benign)")

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=20000,
        sublinear_tf=True,
        lowercase=True,
    )
    X_train = vectorizer.fit_transform(train_x)
    X_test = vectorizer.transform(test_x)
    print(f"vocabulary: {len(vectorizer.vocabulary_)} features")

    clf = LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0)
    clf.fit(X_train, train_y)

    train_p = clf.predict_proba(X_train)[:, 1]
    test_p = clf.predict_proba(X_test)[:, 1]

    for name, y, p in (("train", train_y, train_p), ("holdout", test_y, test_p)):
        prec, rec, fpr, (tp, fp, fn, tn) = metrics(y, p, 0.5)
        print(f"{name:8s} @0.50  precision={prec:.3f}  recall={rec:.3f}  "
              f"FPR={fpr:.3f}  (tp={tp} fp={fp} fn={fn} tn={tn})")

    # Behavior at the fusion thresholds brain.py actually uses.
    prec, rec, fpr, _ = metrics(test_y, test_p, 0.85)
    print(f"holdout @0.85 (ml-only flag threshold): "
          f"precision={prec:.3f} recall={rec:.3f} FPR={fpr:.3f}")
    prec, rec, fpr, _ = metrics(test_y, test_p, 0.50)
    print(f"holdout @0.50 (ml confirm threshold):   "
          f"precision={prec:.3f} recall={rec:.3f} FPR={fpr:.3f}")

    bundle = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "meta": {
            "dataset": "deepset/prompt-injections",
            "dataset_url": "https://huggingface.co/datasets/deepset/prompt-injections",
            "license": "Apache 2.0",
            "ngram_range": (1, 2),
            "max_features": 20000,
            "sublinear_tf": True,
            "classifier": "LogisticRegression(max_iter=1000, class_weight=balanced, C=1.0)",
            "train_rows": len(train_x),
            "sklearn_version": __import__("sklearn").__version__,
        },
    }
    with open(OUT, "wb") as f:
        pickle.dump(bundle, f, protocol=4)
    size_mb = os.path.getsize(OUT) / (1024 * 1024)
    print(f"saved {OUT} ({size_mb:.2f} MB) in {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
