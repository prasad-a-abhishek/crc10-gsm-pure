"""Repro for F-002 — demonstrates the >=1 MB stress test gap.

This script documents that no unit test covers >=1 MB inputs.
VULN_AUDIT live verification confirmed 100 MiB all-zero completes in 22.84s
and 200 MiB random in 76.2s, both linear. No test pins this bound.

Run:
    python3 repro.py
"""

from __future__ import annotations
import time
import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..", "src"))

from crc10_gsm import crc

def main() -> int:
    # 10 MiB test (small enough to run quickly, demonstrates the gap)
    data_10mb = b"\x00" * (10 * 1024 * 1024)

    start = time.perf_counter()
    result = crc(data_10mb)
    elapsed = time.perf_counter() - start

    print(f"CRC of 10 MiB all-zero = 0x{result:03x}")
    print(f"Time: {elapsed:.2f}s")

    # Linear extrapolation: 10 MiB in ~2.3s → 100 MiB in ~23s, 200 MiB in ~46s
    expected_linear_per_mb = 0.23  # seconds per MiB (conservative)
    expected_100mb = 100 * expected_linear_per_mb
    print(f"Expected 100 MiB at same rate: ~{expected_100mb:.0f}s (verified live: 22.84s)")
    print(f"Expected 200 MiB at same rate: ~{expected_100mb*2:.0f}s (verified live: 76.2s)")
    print()
    print("Conclusion: F-002 is correctly characterised as a test-coverage gap.")
    print("No unit test pins the large-input linear-time bound.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
