#!/usr/bin/env python3
"""Live demo runner — one input per invocation, session state on disk.

Usage:
    python3 play.py "your attack here" [--session NAME] [--reset]

The architect throws attacks in chat; each reply shows the trap's verdict.
State (gnat index, history, lockout, template memory, golden seams) persists
in sessions/, so a red-team run survives across turns.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from gnat_trap import GnatTrapEngine  # noqa: E402

SESSIONS = os.path.join(ROOT, "sessions")


def state_path(name):
    return os.path.join(SESSIONS, f"{name}.json")


def seams_path(name):
    return os.path.join(SESSIONS, f"{name}-seams.json")


def load(name):
    try:
        with open(state_path(name), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save(name, eng):
    os.makedirs(SESSIONS, exist_ok=True)
    with open(state_path(name), "w", encoding="utf-8") as f:
        json.dump(
            {
                "index": eng.index,
                "history": eng.history,
                "locked": eng.locked,
                # tuple keys -> "tier:idx" strings for JSON
                "memory": {f"{t}:{i}": n for (t, i), n in eng.memory._uses.items()},
                "session_id": eng.log.session,
            },
            f,
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?",
                    help="the attack (or message) to throw at the trap")
    ap.add_argument("--session", default="live")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument(
        "--learn-miss",
        metavar="VECTOR",
        default=None,
        help="gild INPUT as a manually-reviewed miss under VECTOR (no verdict)",
    )
    ap.add_argument(
        "--fuzz", type=int, default=0, metavar="N",
        help="fire N randomized obfuscated attacks at a fresh session",
    )
    ap.add_argument("--seed", type=int, default=7,
                    help="fuzz RNG seed (deterministic)")
    a = ap.parse_args()

    if a.fuzz:
        from gnat_trap.fuzz import generate
        from gnat_trap.detector import scan
        batch = generate(a.fuzz, seed=a.seed)
        # Stateless detection benchmark: scan() with no session, so the
        # escalation ladder's red-tier lockout can't masquerade as misses.
        caught = 0
        for atk in batch:
            result = scan(atk["text"])
            caught += result.is_gnat
            vecs = sorted({d.vector for d in result.detections})
            mark = "GNAT " if result.is_gnat else "MISS!"
            print(f"[{mark}] {atk['id']} score={result.gnat_score:.2f} "
                  f"vectors={','.join(vecs) or '-'}")
        print(f"\nFUZZ: {caught}/{len(batch)} caught "
              f"({100.0 * caught / len(batch):.1f}%) — seed {a.seed}")
        return

    if not a.input:
        ap.error("input is required unless --fuzz is given")

    if a.reset:
        for p in (state_path(a.session), seams_path(a.session)):
            if os.path.exists(p):
                os.remove(p)

    st = load(a.session)
    eng = GnatTrapEngine(
        session_id=st["session_id"] if st else None,
        seams_path=seams_path(a.session),
    )
    if st:
        eng.index = st["index"]
        eng.history = st["history"]
        eng.locked = st["locked"]
        eng.memory._uses = {
            (k.rsplit(":", 1)[0], int(k.rsplit(":", 1)[1])): n
            for k, n in st["memory"].items()
        }

    rec = eng.process(a.input)
    save(a.session, eng)

    if a.learn_miss:
        seam = eng.kintsugi.learn_miss(a.input, a.learn_miss, note="arena review")
        if seam:
            print(f"[GILDED] miss learned as '{a.learn_miss}' "
                  f"(provenance: manual). The trap won't miss this shape again.")
        else:
            print("[GILDED] input too thin to gild — needs 2+ signature words.")
        return

    if rec["tier"] == "clear":
        print(f"[CLEAR] score={rec['gnat_score']:.2f} — pass-through. The trap stays silent.")
    elif rec["tier"] == "locked":
        print(f"[LOCKED] {rec['response']}")
    else:
        print(
            f"[GNAT #{rec['gnat_index']} · {rec['tier'].upper()} · "
            f"score={rec['gnat_score']:.2f} · {','.join(rec['vectors'])}]"
        )
        print(f"Trap: {rec['response']}")
        if rec["tier"] == "red":
            print("(session locked — new arena: --session NAME)")


if __name__ == "__main__":
    main()
