#!/usr/bin/env python3
"""Surface 3: CLI --stdin — raw byte input (empty, 1B, 1KiB, 1MiB, CRLF, null bytes).

The --stdin path reads sys.stdin.buffer.read() (raw bytes, not stripped) and
passes them directly to crc().  This harness exercises boundary conditions on
the I/O path.

Stdlib-only.  Exit 0 = all clean, 1 = crash.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

MAX_ITERS = 100


def run_cli_stdin(stdin_data: bytes) -> tuple[int, bytes, bytes]:
    """Run crc10-gsm --stdin feeding stdin_data; return (exit_code, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, "-m", "crc10_gsm", "--stdin"],
        input=stdin_data,
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def is_valid_hex_output(out: bytes) -> bool:
    return (
        len(out.strip()) > 0
        and out.strip().startswith(b"0x")
        and len(out.strip()) <= 7
    )


def suite_empty_and_small() -> int:
    """Empty and tiny stdin payloads."""
    crashes = 0
    cases = [
        (b"",                        "empty stdin"),
        (b"\x00",                    "single null byte"),
        (b"\xff",                    "single 0xFF"),
        (b"A",                       "single ASCII letter"),
        (b"123456789",               "canonical 9-byte"),
        (b"\x00\x01\x02",            "null + small bytes"),
        (b"\xff\xfe\xfd",            "high bytes"),
    ]
    for data, label in cases:
        code, stdout, stderr = run_cli_stdin(data)
        if code != 0:
            print(f"  FAIL {label}: exit {code}, stderr={stderr[:200]!r}", file=sys.stderr)
            crashes += 1
        elif not is_valid_hex_output(stdout):
            print(f"  FAIL {label}: bad output {stdout!r}", file=sys.stderr)
            crashes += 1
    return crashes


def suite_crlf_and_binary() -> int:
    """CRLF, null bytes, and binary edge cases in stdin."""
    crashes = 0
    cases = [
        (b"\r\n",                    "CRLF only"),
        (b"hello\r\n",               "text + CRLF"),
        (b"line1\r\nline2\r\n",      "two lines CRLF"),
        (b"\x00\x00\x00",            "multiple nulls"),
        (b"\xff\xff\xff",            "multiple 0xFF"),
        (b"\x00\xff\x00\xff",        "alternating null/0xFF"),
        (b"\x80\x81\x82",            "high-bit bytes"),
        (b"a\x00b\x00c",             "null interleaved in text"),
        (b"\xc0\xc1",                "UTF-8 lead bytes"),
        (b"\xfe\xff",                "BOM-like bytes"),
    ]
    for data, label in cases:
        code, stdout, stderr = run_cli_stdin(data)
        if code != 0:
            print(f"  FAIL {label}: exit {code}", file=sys.stderr)
            crashes += 1
        elif not is_valid_hex_output(stdout):
            print(f"  FAIL {label}: bad output {stdout!r}", file=sys.stderr)
            crashes += 1
    return crashes


def suite_large_inputs(max_kb: int = 1) -> int:
    """Large stdin payloads (default 1 KiB; use --max-kb to raise)."""
    crashes = 0
    patterns = [
        (lambda n: bytes(0x00 for _ in range(n)),    "all-zero"),
        (lambda n: bytes(0xFF for _ in range(n)),    "all-0xFF"),
        (lambda n: bytes(i & 0xFF for i in range(n)), "sequential"),
        (lambda n: bytes((0x55 ^ i) & 0xFF for i in range(n)), "alternating-0x55"),
    ]
    sizes_kb = [1, 4, max_kb]
    for pattern_fn, pname in patterns:
        for size_kb in sizes_kb:
            if size_kb > max_kb:
                continue
            size = size_kb * 1024
            data = pattern_fn(size)
            code, stdout, stderr = run_cli_stdin(data)
            if code != 0:
                print(f"  FAIL large {pname} {size_kb}KiB: exit {code}", file=sys.stderr)
                crashes += 1
            elif not is_valid_hex_output(stdout):
                print(f"  FAIL large {pname} {size_kb}KiB: bad output {stdout!r}", file=sys.stderr)
                crashes += 1
    return crashes


def suite_random_fuzz(rng, iters: int) -> int:
    """Generate random byte payloads and verify no crashes."""
    crashes = 0
    for _ in range(iters):
        size = rng.randint(0, 4096)  # up to 4 KiB for fuzzing
        data = rng.randbytes(size)
        code, stdout, stderr = run_cli_stdin(data)
        if code != 0:
            print(f"  FAIL fuzz {size}B: exit {code}", file=sys.stderr)
            crashes += 1
        elif not is_valid_hex_output(stdout):
            print(f"  FAIL fuzz {size}B: bad output {stdout!r}", file=sys.stderr)
            crashes += 1
    return crashes


def run(iters: int, seed: int, max_kb: int) -> int:
    import random
    rng = random.Random(seed)
    t0 = time.monotonic()

    print("  running empty_and_small suite…")
    c1 = suite_empty_and_small()
    print(f"    empty_and_small: crashes={c1}")

    print("  running crlf_and_binary suite…")
    c2 = suite_crlf_and_binary()
    print(f"    crlf_binary: crashes={c2}")

    print(f"  running large_inputs suite (max {max_kb}KiB)…")
    c3 = suite_large_inputs(max_kb)
    print(f"    large_inputs: crashes={c3}")

    print(f"  running random fuzz ({iters} iters)…")
    c4 = suite_random_fuzz(rng, iters)
    print(f"    random_fuzz: crashes={c4}")

    dt = time.monotonic() - t0
    total = c1 + c2 + c3 + c4
    print(f"[cli_stdin] iters={iters} max_kb={max_kb} crashes={total} time={dt:.2f}s")
    return 1 if total else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harness_cli_stdin: fuzz CLI --stdin raw bytes")
    ap.add_argument("--iters", type=int, default=MAX_ITERS)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-kb", type=int, default=1, help="largest stdin payload in KiB (default 1)")
    args = ap.parse_args()
    sys.exit(run(args.iters, args.seed, args.max_kb))
