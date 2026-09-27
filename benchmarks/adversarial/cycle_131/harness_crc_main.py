#!/usr/bin/env python3
"""Surface 1: crc() core API — stdin -> crc() -> stdout hex, must not raise.

Fuzzes the CRC-10/GSM function with random byte payloads of bounded length.
Asserts two Invariant-21-shaped invariants:
  1. return value is an int
  2. return value lies in the 10-bit range [0, 0x3FF]

Stdlib-only: no Atheris/libFuzzer.  Exit 0 = clean, 1 = crash.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time

# Ensure the local package is on sys.path so we can import it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "src"))

from crc10_gsm import crc

MAX_ITERS = 100
MAX_DATA_KB = 64          # max random payload size in KiB


def canonical_vectors() -> list[bytes]:
    """Known-answer vectors from the RevEng catalogue.

    The only fully-specified RevEng entries for CRC-10/GSM are:
      b""           → 0x3FF
      b"123456789"  → 0x12A  (the official check value)

    All other cases below are computed from the package itself and are
    included only to exercise range / no-crash / determinism, not as
    authoritative oracles.
    """
    known = [
        (b"",          0x3FF),   # RevEng catalogue: empty input
        (b"123456789", 0x12A),   # RevEng catalogue: check value
    ]
    computed = [
        (b"\x00",      "single 0x00 byte — range check only"),
        (b"\xff",      "single 0xFF byte — range check only"),
        (b"A",         "text byte A — range check only"),
        (b"Hi",        "two-byte text — range check only"),
        (b"\x80" * 10, "10× msb byte — range check only"),
    ]

    for data, expected in known:
        result = crc(data)
        assert isinstance(result, int), f"non-int on {data!r}: {type(result)}"
        assert 0 <= result <= 0x3FF, f"out-of-range on {data!r}: 0x{result:X}"
        assert result == expected, f"canonical mismatch on {data!r}: got 0x{result:X}, want 0x{expected:X}"

    for data, _label in computed:
        result = crc(data)
        assert isinstance(result, int), f"non-int on {data!r}: {type(result)}"
        assert 0 <= result <= 0x3FF, f"out-of-range on {data!r}: 0x{result:X}"

    return [data for data, _ in known + computed]


def stress_patterns() -> list[bytes]:
    """Large stress patterns that expose edge-case bit folding."""
    patterns = []
    # 1 KiB blocks of each pattern type (smoke = 1 KiB, not 1 MiB, for speed)
    for size_kb in [1, 4]:
        size = size_kb * 1024
        patterns.extend([
            bytes(0x00 for _ in range(size)),            # all-zero
            bytes(0xFF for _ in range(size)),            # all-0xFF
            bytes(i & 0xFF for i in range(size)),       # sequential 0..255 wrap
            bytes((0x55 ^ i) & 0xFF for i in range(size)),  # alternating base 0x55
        ])
    return patterns


def fuzz_random(rng: random.Random, iters: int) -> tuple[int, float]:
    """Random byte payloads, bounded length."""
    crashes = 0
    start = time.monotonic()
    for _ in range(iters):
        size = rng.randint(0, MAX_DATA_KB * 1024)
        data = rng.randbytes(size)
        try:
            result = crc(data)
            assert isinstance(result, int), f"non-int: {type(result).__name__}"
            assert 0 <= result <= 0x3FF, f"out-of-range: 0x{result:X}"
        except Exception as exc:
            crashes += 1
            print(f"  CRASH on random {size}B: {type(exc).__name__}: {exc}", file=sys.stderr)
    return crashes, time.monotonic() - start


def run(iters: int, seed: int) -> int:
    """Run all suites; return 0 on success, 1 on any crash."""
    rng = random.Random(seed)
    total_crashes = 0

    # 1. Canonical vectors (determinism + correctness oracle)
    print(f"  running canonical ({len(canonical_vectors())} vectors)…")
    crashes, dt = 0, 0.0
    try:
        canonical_vectors()
    except Exception as exc:
        crashes = 1
        print(f"  CRASH canonical: {exc}", file=sys.stderr)
    print(f"    canonical: crashes={crashes} time={dt:.2f}s")

    # 2. Stress patterns (large / edge-case payloads)
    print(f"  running stress patterns…")
    st = time.monotonic()
    crashes = 0
    for pattern in stress_patterns():
        try:
            result = crc(pattern)
            assert isinstance(result, int) and 0 <= result <= 0x3FF
        except Exception as exc:
            crashes += 1
            print(f"  CRASH stress {len(pattern)}B {pattern[:4]!r}: {exc}", file=sys.stderr)
    sd = time.monotonic() - st
    print(f"    stress: crashes={crashes} time={sd:.2f}s")
    total_crashes += crashes

    # 3. Random fuzz
    print(f"  running random ({iters} iters, seed={seed})…")
    rc, rt = fuzz_random(rng, iters)
    total_crashes += rc
    print(f"    random: crashes={rc} time={rt:.2f}s")

    return 1 if total_crashes else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harness_crc_main: fuzz crc() core API")
    ap.add_argument("--iters", type=int, default=MAX_ITERS)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    t0 = time.monotonic()
    exit_code = run(args.iters, args.seed)
    total = time.monotonic() - t0
    print(f"[crc_main] iters={args.iters} crashes={exit_code} time={total:.2f}s")
    sys.exit(exit_code)
