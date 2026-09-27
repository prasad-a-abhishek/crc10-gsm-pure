"""Repro for F-003 — demonstrates the stdin binary-variant test gap.

This script verifies the stdin binary-contract behaviour that is not pinned
in the test suite.

Run:
    python3 repro.py
"""

from __future__ import annotations
import subprocess
import sys

def main() -> int:
    cases = [
        # (name, stdin_bytes, expected_crc_hex)
        ("CRLF input",      b"123456789\r\n", "0x342"),
        ("binary bytes",    b"\x00\xff\x7f\x80", "0x050"),
        ("empty stdin",     b"", "0x3ff"),
        ("all zeros 4B",    b"\x00\x00\x00\x00", "0x3ff"),
        ("all ones 4B",     b"\xff\xff\xff\xff", "0x07f"),
    ]

    all_ok = True
    for name, data, expected in cases:
        result = subprocess.run(
            [sys.executable, "-m", "crc10_gsm", "--stdin"],
            input=data,
            capture_output=True,
            timeout=10,
        )
        # stdout may be bytes or str depending on platform buffering
        raw = result.stdout
        actual = raw.strip().decode("utf-8") if isinstance(raw, bytes) else raw.strip()
        status = "OK" if actual == expected else "MISMATCH"
        if actual != expected:
            all_ok = False
        print(f"{name}: {actual!r} (expected {expected!r}) [{status}]")

    print()
    if all_ok:
        print("All behaviours confirmed. No test in suite pins these values.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
