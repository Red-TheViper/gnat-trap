# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""Sundew — the optional ML brain sidecar for Gnat Trap (v1.2.0).

An ML stage that sits *underneath* the heuristic layer: it can confirm a
heuristic flag or catch what the heuristics miss, but it can never
overrule them. When no trained model file is present Sundew is fully
inert and detector.scan() behaves exactly like v1.1.0.

Top-level imports are stdlib ONLY. scikit-learn is imported lazily inside
load_model()/brain_score() and ImportError is swallowed, so
``from gnat_trap import brain`` works with zero third-party packages
installed. The model bundle is a plain pickle of
{"vectorizer": TfidfVectorizer, "classifier": LogisticRegression, ...},
produced by eval/train_brain.py from a public labeled dataset.

Trust note: pickle executes code on load. Only load model files you
trained yourself (eval/train_brain.py) — never a stranger's .pkl.
"""
from __future__ import annotations

import os
import pickle
from functools import lru_cache

# ------------------------------------------------------------------ config
DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "brain_model.pkl"
)

# Fusion thresholds (kept in sync with detector.GNAT_THRESHOLD = 0.55).
HEURISTIC_FLAG_THRESHOLD = 0.55  # a heuristic score >= this is already a gnat
ML_FLAG_THRESHOLD = 0.85         # clean heuristics + ml >= this -> ML-only flag
ML_CONFIRM_THRESHOLD = 0.50      # flagged heuristics + ml >= this -> confirm bump
ML_CONFIRM_BUMP = 0.05           # max score added by an ML confirmation
ML_ONLY_SCORE = 0.80             # score assigned to an ML-only flag


# ------------------------------------------------- availability (cached)
@lru_cache(maxsize=8)
def _file_exists(path: str) -> bool:
    return os.path.exists(path)


def brain_available(path: str | None = None) -> bool:
    """True if a trained model file exists. Cached — cheap after first call."""
    return _file_exists(path or DEFAULT_MODEL_PATH)


def refresh() -> None:
    """Clear the cached file-exists check and model cache.

    Call after dropping in (or removing) a brain_model.pkl so a long-lived
    process picks up the change without a restart.
    """
    _file_exists.cache_clear()
    _MODEL_CACHE.clear()


# ------------------------------------------------------------ model loading
_MODEL_CACHE: dict[str, tuple | None] = {}


def load_model(path: str | None = None) -> tuple | None:
    """Load the (vectorizer, classifier) bundle.

    Returns None — never raises — if scikit-learn is missing, the file is
    missing, or the bundle is unreadable/corrupt.
    """
    try:
        import sklearn  # noqa: F401  (prove it's importable; used below)
    except ImportError:
        return None
    del sklearn

    model_path = path or DEFAULT_MODEL_PATH
    try:
        with open(model_path, "rb") as f:
            bundle = pickle.load(f)
    except Exception:
        return None

    try:
        if isinstance(bundle, dict):
            vectorizer, classifier = bundle["vectorizer"], bundle["classifier"]
        else:  # tuple/list of (vectorizer, classifier)
            vectorizer, classifier = bundle[0], bundle[1]
        if not (hasattr(vectorizer, "transform") and hasattr(classifier, "predict")):
            return None
        return (vectorizer, classifier)
    except Exception:
        return None


def get_model(path: str | None = None) -> tuple | None:
    """load_model() with a process-wide cache. Use refresh() to invalidate."""
    key = os.path.abspath(path or DEFAULT_MODEL_PATH)
    if key not in _MODEL_CACHE:
        _MODEL_CACHE[key] = load_model(key)
    return _MODEL_CACHE[key]


# ------------------------------------------------------------------ scoring
def brain_score(text: str, model: tuple | None) -> float | None:
    """P(malicious) for one input, 0.0-1.0. None if there is no model.

    TF-IDF transform + LogisticRegression predict: single-digit
    milliseconds on CPU.
    """
    if model is None:
        return None
    try:
        vectorizer, classifier = model
        vec = vectorizer.transform([text or ""])
        if hasattr(classifier, "predict_proba"):
            proba = float(classifier.predict_proba(vec)[0][1])
        else:  # pragma: no cover — LogisticRegression always has proba
            import math

            logit = float(classifier.decision_function(vec)[0])
            proba = 1.0 / (1.0 + math.exp(-logit))
    except Exception:
        return None
    return min(1.0, max(0.0, proba))


# ------------------------------------------------------------------- fusion
def fuse(
    heuristic_score: float,
    heuristic_detections: list,
    ml_score: float | None,
) -> tuple[float, list]:
    """Fuse the heuristic verdict with the Sundew ML sidecar score.

    Fusion rule (Sundew is advisory — heuristics rule):

    1. ml_score is None (no model / sklearn missing) -> return the
       heuristics untouched. v1.1.0 behavior, bit for bit.
    2. Heuristics already flag (heuristic_score >= 0.55): the ML score can
       only CONFIRM. If ml_score >= 0.50 the score gets a small bump of at
       most +0.05 (capped at 1.0) and a Detection(vector="ml_signal",
       score=<ml_score>) is appended as provenance. If the ML score is low
       the heuristic flag stands unchanged — ML never lowers a flag.
    3. Heuristics are clean but ml_score >= 0.85: the brain fires alone.
       Appends Detection(vector="ml_signal", score=0.8) and returns score
       0.8, so the input flags as a gnat.
    4. Heuristics clean and ml_score < 0.85: returned untouched. ML never
       raises a clean input on a lukewarm signal.
    """
    # Imported lazily to keep this module's top level stdlib-only and to
    # avoid any import cycle with detector (which imports this module).
    from .detector import Detection, GNAT_THRESHOLD

    ml = None if ml_score is None else min(1.0, max(0.0, float(ml_score)))
    if ml is None:
        return heuristic_score, heuristic_detections

    detections = list(heuristic_detections)
    if heuristic_score >= GNAT_THRESHOLD:
        # Already a gnat: ML confirms, never overrules.
        if ml >= ML_CONFIRM_THRESHOLD:
            score = min(1.0, round(heuristic_score + ML_CONFIRM_BUMP, 3))
            detections.append(
                Detection(
                    vector="ml_signal",
                    score=round(ml, 3),
                    evidence=f"ml confirm p={ml:.2f}",
                )
            )
            return score, detections
        return heuristic_score, detections

    # Heuristics clean: only a strong ML signal may raise the input.
    if ml >= ML_FLAG_THRESHOLD:
        detections.append(
            Detection(
                vector="ml_signal",
                score=ML_ONLY_SCORE,
                evidence=f"ml-only flag p={ml:.2f}",
            )
        )
        return ML_ONLY_SCORE, detections
    return heuristic_score, heuristic_detections
