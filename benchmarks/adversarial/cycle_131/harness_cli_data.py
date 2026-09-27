#!/usr/bin/env python3
"""Surface 2/4: CLI --data flag — valid, malformed, CRLF, unicode hex strings.

The _parse_data() helper is the main I/O attack surface: it tries
bytes.fromhex → int(v,16) → int(v) → latin-1 fallback.  This harness
exercises every tier including the latin-1 surprise.

Stdlib-only.  Exit 0 = all inputs handled cleanly, 1 = crash.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

sys.path.insert(0, "src")

MAX_ITERS = 100


def run_cli_data(argv: list[str]) -> tuple[int, str, str]:
    """Run crc10-gsm with given argv; return (exit_code, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, "-m", "crc10_gsm"] + argv,
        capture_output=True, text=False,
        # Force fresh import to catch any subprocess-level state issues
    )
    return proc.returncode, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")


def is_valid_hex_output(out: str) -> bool:
    """Check that stdout looks like '0x<3-hex-digits>'."""
    return bool(out.strip().startswith("0x")) and len(out.strip()) <= 7


def suite_canonical() -> int:
    """Known-good --data inputs that must produce valid hex output."""
    crashes = 0
    cases = [
        # (argv, description)
        (["--data", "313233343536373839"], "canonical 123456789 as hex"),
        (["--data", "31", "32", "33"], "canonical as separate args"),
        (["--data", "00"], "empty-byte as hex"),
        (["--data", "ff"], "0xFF as lowercase hex"),
        (["--data", "A1B2C3"], "mixed-case hex"),
        (["--data", "a1b2c3"], "lowercase hex"),
        (["--data", "FFFF"], "all-F hex"),
        (["--data", "0000"], "all-zero hex"),
        (["--data", "01"], "single byte hex"),
        (["--data", ""], "empty string arg (latin-1 fallback — exits 0)"),
    ]
    for argv, label in cases:
        code, stdout, stderr = run_cli_data(argv)
        stdout_s = stdout.strip()
        # Even the latin-1 fallback for "" must exit 0 with a valid hex line
        if code != 0:
            print(f"  FAIL canonical {label}: exit {code}, stderr={stderr[:200]!r}", file=sys.stderr)
            crashes += 1
        elif not is_valid_hex_output(stdout_s):
            print(f"  FAIL canonical {label}: bad output {stdout_s!r}", file=sys.stderr)
            crashes += 1
    return crashes


def suite_malformed() -> int:
    """Malformed hex inputs that must NOT produce a Python traceback."""
    crashes = 0
    cases = [
        # (argv, description)
        (["--data", "ZZZZ"], "non-hex latin-1 fallback (4×0x5A)"),
        (["--data", "GGG"], "invalid hex → latin-1 fallback"),
        (["--data", "1"], "odd-length hex (rejected by fromhex → latin-1 fallback)"),
        (["--data", "GGGGGGGG"], "8-char invalid hex → latin-1 fallback"),
        (["--data", "0x41", "0x42"], "explicit 0x prefix"),
        (["--data", "0x41", "0x42", "0x43"], "multiple 0x prefix"),
        (["--data", "255"], "decimal fallback (int(v) → & 0xFF)"),
        (["--data", "1", "2", "3"], "decimal bytes as separate args"),
        (["--data", "31 32 33"], "space-separated hex in single arg"),
        (["--data", "31\n32\n33"], "newline-separated hex (latin-1 fallback to literal)"),
        (["--data", "A", "B", "C"], "single-char args → int(v,16)"),
    ]
    for argv, label in cases:
        code, stdout, stderr = run_cli_data(argv)
        if "Traceback" in stderr:
            print(f"  FAIL malformed {label}: traceback in stderr:\n{stderr[:300]}", file=sys.stderr)
            crashes += 1
        elif code not in (0, 2):  # 2 = argparse invalid flag
            print(f"  FAIL malformed {label}: unexpected exit {code}", file=sys.stderr)
            crashes += 1
    return crashes


def suite_crlf_unicode() -> int:
    """CRLF, unicode, and whitespace in hex strings."""
    crashes = 0
    cases = [
        # Valid hex with CRLF padding
        (["--data", "31\r\n32\r\n33"], "CRLF in hex string"),
        (["--data", "31 32\r\n33"], "mixed CRLF"),
        # Unicode chars (some may be rejected by int(v,16), falling to latin-1)
        (["--data", "41\xe2\x80\x94"], "em-dash unicode after hex"),
    ]
    for argv, label in cases:
        code, stdout, stderr = run_cli_data(argv)
        if "Traceback" in stderr:
            print(f"  FAIL crlf/unicode {label}: traceback:\n{stderr[:300]}", file=sys.stderr)
            crashes += 1
    return crashes


def suite_random_fuzz(rng, iters: int) -> int:
    """Generate random hex-like strings and verify no crashes."""
    crashes = 0
    chars = "0123456789ABCDEFabcdef"
    for _ in range(iters):
        length = rng.randint(1, 64) * 2  # ensure even
        hex_str = "".join(rng.choices(chars, k=length))
        code, stdout, stderr = run_cli_data(["--data", hex_str])
        if code != 0:
            print(f"  FAIL fuzz hex={hex_str[:20]!r}: exit {code}", file=sys.stderr)
            crashes += 1
        elif not is_valid_hex_output(stdout.strip()):
            print(f"  FAIL fuzz hex={hex_str[:20]!r}: bad output {stdout.strip()!r}", file=sys.stderr)
            crashes += 1
    return crashes


def run(iters: int, seed: int) -> int:
    import random
    rng = random.Random(seed)

    t0 = time.monotonic()

    print("  running canonical suite…")
    c1 = suite_canonical()
    print(f"    canonical: crashes={c1}")

    print("  running malformed suite…")
    c2 = suite_malformed()
    print(f"    malformed: crashes={c2}")

    print("  running CRLF/unicode suite…")
    c3 = suite_crlf_unicode()
    print(f"    crlf_unicode: crashes={c3}")

    print(f"  running random fuzz ({iters} iters)…")
    c4 = suite_random_fuzz(rng, iters)
    print(f"    random_fuzz: crashes={c4}")

    dt = time.monotonic() - t0
    total = c1 + c2 + c3 + c4
    print(f"[cli_data] iters={iters} crashes={total} time={dt:.2f}s")
    return 1 if total else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harness_cli_data: fuzz CLI --data flag")
    ap.add_argument("--iters", type=int, default=MAX_ITERS)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    sys.exit(run(args.iters, args.seed))
