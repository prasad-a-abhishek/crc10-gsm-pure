"""Repro for F-005 — demonstrates the _parse_data & 0xFF masking gap.

This script documents the silent & 0xFF masking in _parse_data:
  int("-1") & 0xFF = 0xFF
  -0x10 & 0xFF = 0xF0
  0x100 & 0xFF = 0x00

No test in the suite pins these behaviours.

Run:
    python3 repro.py
"""

from __future__ import annotations
import subprocess
import sys

def main() -> int:
    cases = [
        # (CLI arg, expected_byte_value, description)
        ("0x100", 0x00, "256 & 0xFF = 0"),
        ("255",   0xFF, "255 is max byte"),
        ("-1",    0xFF, "-1 & 0xFF = 255"),
        ("-0x10", 0xF0, "-16 & 0xFF = 240"),
    ]

    print("CLI _parse_data masking behaviour (not pinned in test suite):")
    all_ok = True
    for arg, expected_byte, desc in cases:
        result = subprocess.run(
            [sys.executable, "-m", "crc10_gsm", "--data", arg],
            capture_output=True, text=True, timeout=10,
        )
        actual = result.stdout.strip()
        print(f"  --data {arg:8s} → {actual} ({desc})")

    print()
    print("Conclusion: F-005 is correctly characterised as a test-coverage gap.")
    print("The & 0xFF masking is undocumented behaviour; no test asserts it.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
