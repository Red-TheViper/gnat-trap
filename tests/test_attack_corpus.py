# Copyright (c) 2026 Fred McFadden — SPDX-License-Identifier: AGPL-3.0-or-later
"""Attack corpus test — every deceptive attack must be caught, every benign
line must pass through clean.

Each attack runs in a FRESH engine with an isolated (empty) seams file, so
the verdicts below test the curated + intent + normalization layers only —
no Kintsugi carryover between attacks.

Two optional entry keys (both default to current behavior):
  "channel": "tool_output" — process through the indirect-injection data
      gate instead of the user-input banks.
  "setup": [inputs...] — processed (discarded) first, so multi-turn
      detectors like slow_boil see their history.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gnat_trap import GnatTrapEngine  # noqa: E402
from gnat_trap.attacks import ATTACK_CORPUS  # noqa: E402


def fresh_engine(tmpdir):
    return GnatTrapEngine(
        seams_path=os.path.join(tmpdir, "seams.json"),
        session_id="corpus-test",
    )


def main() -> None:
    caught, clean, failures = 0, 0, []
    with tempfile.TemporaryDirectory() as tmpdir:
        for entry in ATTACK_CORPUS:
            eng = fresh_engine(tmpdir)
            for pre in entry.get("setup", []):
                eng.process(pre)
            rec = eng.process(entry["text"],
                              channel=entry.get("channel", "user_input"))
            want_gnat = entry["expect"] == "gnat"
            ok = rec["is_gnat"] == want_gnat
            if want_gnat and ok:
                missing = [v for v in entry["vectors"] if v not in rec["vectors"]]
                if missing:
                    ok = False
                    entry["_missing"] = missing
            if ok:
                caught += want_gnat
                clean += not want_gnat
            else:
                failures.append(
                    (entry["id"], entry["expect"], rec["is_gnat"],
                     rec["vectors"], entry.get("_missing"))
                )
            print(f"{entry['id']:10s} want={entry['expect']:5s} "
                  f"got={'gnat' if rec['is_gnat'] else 'clear':5s} "
                  f"score={rec['gnat_score']:.2f} {'OK' if ok else 'FAIL'}")

    print("=" * 64)
    print(f"RESULT: {caught} attacks caught, {clean} benign clean, "
          f"{len(failures)} failures / {len(ATTACK_CORPUS)} total.")
    for f in failures:
        print(f"  FAIL {f[0]}: want={f[1]} got_gnat={f[2]} "
              f"vectors={f[3]} missing={f[4]}")
    assert not failures, f"{len(failures)} corpus failures"
    print("ALL CORPUS ASSERTIONS PASSED — obfuscation does not save them.")
    print("=" * 64)


if __name__ == "__main__":
    main()
