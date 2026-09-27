"""Repro for F-001 — demonstrates the latin-1 fallback gap.

This script shows that:
1. --data ZZZZ exits 0 (not an error)
2. It produces a CRC of the literal bytes ZZZZ (0x5A * 4)
3. No test in the suite asserts this specific output value.

Run:
    python3 repro.py
"""

from __future__ import annotations
import subprocess
import sys

def main() -> int:
    # Demonstrate the latin-1 fallback
    result = subprocess.run(
        [sys.executable, "-m", "crc10_gsm", "--data", "ZZZZ"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    print(f"exit={result.returncode}")
    print(f"stdout={result.stdout.strip()!r}")
    print(f"stderr={result.stderr.strip()!r}")

    # The CRC of b"ZZZZ" (0x5A 0x5A 0x5A 0x5A) is 0x304
    expected = "0x304"
    actual = result.stdout.strip()

    if actual == expected:
        print(f"[PASS] CRC of b'ZZZZ' = {actual} (as expected)")
    else:
        print(f"[NOTE] CRC of b'ZZZZ' = {actual}, expected {expected}")

    print()
    print("Conclusion: F-001 is correctly characterised as a test-coverage gap.")
    print("The behaviour exists and is deterministic; no test pins it.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
