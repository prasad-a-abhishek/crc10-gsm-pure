#!/usr/bin/env python3
"""Surface 1 (algorithm fidelity): cross-cycle oracle vs crc10-atm-pure (cycle_114).

CRC-10/ATM (ITU-T I.432 HEC, poly=0x175, init=0x000, xorout=0x3FF but
refin/refout=True) is a DIFFERENT algorithm than CRC-10/GSM (refin/refout=False).
On the same input the two CRCs MUST produce different results — if they match
for ANY input, that is a strong signal that both algorithms are degenerate.

This harness:
  1. Checks that crc10-atm-pure (cycle_114) is importable; if not → SKIP with exit 0
  2. Runs determinism oracle: 1000-repeat of crc(gns) must return identical int
  3. Runs cross-cycle oracle: every random input must produce DIFFERENT outputs
     from crc10_gsm vs crc10_atm — if they match for ANY input that's a finding

Stdlib-only.  Exit 0 = all checks pass (clean OR SKIP), 1 = finding.
"""
from __future__ import annotations

import argparse
import random
import sys
import time

sys.path.insert(0, "src")
from crc10_gsm import crc

MAX_ITERS = 100
DET_ITERS = 1000


def run(iters: int, det_iters: int, seed: int) -> int:
    """Return 0 on clean, 1 on finding."""
    findings = 0
    t0 = time.monotonic()

    # ── 1. Determinism oracle ──────────────────────────────────────────────
    print(f"  running determinism oracle ({det_iters} repeat calls on b'123456789')…")
    rng = random.Random(seed)
    canonical = b"123456789"
    results = []
    for _ in range(det_iters):
        results.append(crc(canonical))
    unique = set(results)
    dt = time.monotonic() - t0
    if len(unique) != 1:
        print(f"  FAIL: non-deterministic on b'123456789': {len(unique)} distinct values: {unique}", file=sys.stderr)
        findings += 1
    else:
        print(f"    determinism: OK — all {det_iters} calls = 0x{results[0]:03X}")

    # ── 2. Cross-cycle oracle ────────────────────────────────────────────────
    print("  checking for crc10-atm-pure…")
    try:
        from crc10_atm_pure import crc10_atm
        atm_available = True
        print("    crc10-atm-pure found — running cross-cycle oracle")
    except ImportError:
        atm_available = False
        print("    crc10-atm-pure NOT installed — SKIP (graceful, exit 0)")

    if atm_available:
        # Cross-cycle: same input → DIFFERENT outputs expected (they are different algos)
        rng2 = random.Random(seed + 1)
        collisions = 0
        for i in range(iters):
            length = rng2.randint(0, 2048)
            data = rng2.randbytes(length)
            gsm_result = crc(data)
            atm_result = crc10_atm(data)
            if gsm_result == atm_result:
                collisions += 1
                print(f"  FINDING: collision at iter {i} (len={length}) — "
                      f"crc10_gsm=0x{gsm_result:03X} == crc10_atm=0x{atm_result:03X}", file=sys.stderr)

        if collisions > 0:
            findings += collisions
            print(f"    cross_cycle: {collisions} COLLISION(S) — possible algorithm copy-paste bug")
        else:
            print(f"    cross_cycle: {iters} inputs — all DIFFERENT outputs (expected, algos are distinct)")

    # ── 3. Known-answer check ────────────────────────────────────────────────
    print("  running known-answer checks (canonical vectors)…")
    canonical_answers = {
        b"":          0x3FF,
        b"\x00":     0x0AD,
        b"\xff":     0x1D9,
        b"123456789": 0x12A,
    }
    for data, expected in canonical_answers.items():
        result = crc(data)
        if result != expected:
            print(f"  FAIL: crc({data!r}) = 0x{result:03X}, want 0x{expected:03X}", file=sys.stderr)
            findings += 1

    total_time = time.monotonic() - t0
    print(f"[cross_cycle] iters={iters} det_iters={det_iters} "
          f"findings={findings} atm_available={atm_available} time={total_time:.2f}s")
    return 1 if findings else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harness_cross_cycle: cross-cycle oracle vs crc10-atm-pure")
    ap.add_argument("--iters", type=int, default=MAX_ITERS)
    ap.add_argument("--det-iters", type=int, default=DET_ITERS)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    sys.exit(run(args.iters, args.det_iters, args.seed))
