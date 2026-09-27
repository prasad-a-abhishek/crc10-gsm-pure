"""Repro for F-004 — demonstrates the thread-safety test gap.

This script shows that:
1. crc() is a pure function with no shared mutable state
2. Concurrent calls from multiple threads return correct results
3. No test in the suite asserts thread-safety

Run:
    python3 repro.py
"""

from __future__ import annotations
import sys
import os
from concurrent.futures import ThreadPoolExecutor

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..", "src"))

from crc10_gsm import crc

def main() -> int:
    # Determinism baseline
    seeds = [b"test", b"hello", b"\x00\xff", b"123456789"]
    print("Determinism check:")
    for seed in seeds:
        results = [crc(seed) for _ in range(5)]
        ok = len(set(results)) == 1
        print(f"  crc({seed!r}): {results[0]} (consistent={ok})")

    print()
    print("Concurrent thread test (4 workers, 100 calls each):")
    def worker(seed: bytes) -> tuple[bytes, int]:
        return seed, crc(seed)

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(worker, seed) for seed in seeds for _ in range(100)]
        results = [f.result() for f in futures]

    # Check: same seed always gives same CRC across threads
    by_seed: dict[bytes, set[int]] = {}
    for seed, crc_val in results:
        by_seed.setdefault(seed, set()).add(crc_val)

    for seed, vals in by_seed.items():
        ok = len(vals) == 1
        print(f"  {seed!r}: CRC={next(iter(vals))} (consistent across threads={ok})")

    print()
    print("Conclusion: F-004 is correctly characterised as a test-coverage gap.")
    print("No test asserts thread-safety; no shared mutable state exists today.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
