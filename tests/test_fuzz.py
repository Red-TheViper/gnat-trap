"""Fuzz test — randomized obfuscated attacks must ALL be caught.

Deterministic: fixed seed, fresh engine per attack, isolated seams.
If this ever fails, the failure id + seed reproduce the exact attack.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gnat_trap import GnatTrapEngine  # noqa: E402
from gnat_trap.fuzz import generate  # noqa: E402

N = 120
SEED = 20260921


def main() -> None:
    batch = generate(N, seed=SEED)
    misses = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for atk in batch:
            eng = GnatTrapEngine(
                seams_path=os.path.join(tmpdir, "seams.json"),
                session_id="fuzz-test",
            )
            rec = eng.process(atk["text"])
            if not rec["is_gnat"]:
                misses.append((atk["id"], atk["base"]))

    print("=" * 64)
    print(f"FUZZ RESULT: {N - len(misses)}/{N} caught (seed {SEED}).")
    for mid, base in misses:
        print(f"  MISS {mid} (base: {base})")
    assert not misses, f"{len(misses)} fuzz attacks walked through"
    print("ALL FUZZ ASSERTIONS PASSED — random obfuscation does not save them.")
    print("=" * 64)


if __name__ == "__main__":
    main()
