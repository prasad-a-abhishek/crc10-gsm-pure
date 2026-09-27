#!/usr/bin/env python3
"""Surface 4: CLI --register flag + register() API — confirm mask to 10 bits.

The register() function returns a dict of algorithm constants.  The --register
CLI flag prints them.  This harness verifies:
  1. register() returns the correct 7-field dict
  2. Every field has the right type and range
  3. --register CLI exits 0 and prints all fields
  4. The _MASK constant (0x3FF) is consistent between the Python module and CLI output

Stdlib-only.  Exit 0 = clean, 1 = crash/finding.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

sys.path.insert(0, "src")
from crc10_gsm import register
from crc10_gsm._crc10_gsm import _MASK, _POLY, _XOROUT

MAX_ITERS = 100


EXPECTED_REGISTER = {
    "width": 10,
    "poly": 0x175,
    "init": 0x000,
    "refin": False,
    "refout": False,
    "xorout": 0x3FF,
    "check": 0x12A,
}


def suite_register_api() -> int:
    """Verify Python register() API returns the correct dict."""
    crashes = 0
    reg = register()
    if not isinstance(reg, dict):
        print(f"  FAIL: register() returned {type(reg).__name__}, want dict", file=sys.stderr)
        return 1
    for key, expected in EXPECTED_REGISTER.items():
        if key not in reg:
            print(f"  FAIL: register() missing key {key!r}", file=sys.stderr)
            crashes += 1
            continue
        if reg[key] != expected:
            print(f"  FAIL: register()[{key!r}] = {reg[key]!r}, want {expected!r}", file=sys.stderr)
            crashes += 1
    # Extra fields should not exist
    extra = set(reg.keys()) - set(EXPECTED_REGISTER.keys())
    if extra:
        print(f"  FAIL: register() has unexpected keys: {extra}", file=sys.stderr)
        crashes += 1
    return crashes


def suite_cli_register() -> int:
    """Verify crc10-gsm --register exits 0 and prints all expected k=v lines."""
    crashes = 0
    proc = subprocess.run(
        [sys.executable, "-m", "crc10_gsm", "--register"],
        capture_output=True, text=False,
    )
    if proc.returncode != 0:
        print(f"  FAIL: --register exited {proc.returncode}", file=sys.stderr)
        crashes += 1
    lines = proc.stdout.decode().strip().split("\n")
    parsed = {}
    for line in lines:
        if "=" in line:
            k, v = line.strip().split("=", 1)
            # Try to parse value
            if v == "False":
                parsed[k] = False
            elif v == "True":
                parsed[k] = True
            else:
                try:
                    parsed[k] = int(v, 0)
                except ValueError:
                    parsed[k] = v
    for key, expected in EXPECTED_REGISTER.items():
        if key not in parsed:
            print(f"  FAIL: --register output missing {key}=", file=sys.stderr)
            crashes += 1
        elif parsed[key] != expected:
            print(f"  FAIL: --register {key}={parsed[key]!r}, want {expected!r}", file=sys.stderr)
            crashes += 1
    return crashes


def suite_mask_constants() -> int:
    """Verify _MASK, _POLY, _XOROUT are consistent with the register() dict."""
    crashes = 0
    reg = register()
    if reg["width"] != 10:
        print(f"  FAIL: width != 10: {reg['width']}", file=sys.stderr)
        crashes += 1
    if _MASK != (1 << reg["width"]) - 1:
        print(f"  FAIL: _MASK=0x{_MASK:X} != 2^10-1=0x3FF", file=sys.stderr)
        crashes += 1
    if reg["poly"] != _POLY:
        print(f"  FAIL: register poly=0x{reg['poly']:X} != _POLY=0x{_POLY:X}", file=sys.stderr)
        crashes += 1
    if reg["xorout"] != _XOROUT:
        print(f"  FAIL: register xorout=0x{reg['xorout']:X} != _XOROUT=0x{_XOROUT:X}", file=sys.stderr)
        crashes += 1
    if reg["check"] != 0x12A:
        print(f"  FAIL: register check=0x{reg['check']:X} != RevEng canonical 0x12A", file=sys.stderr)
        crashes += 1
    return crashes


def suite_random_register_fuzz(rng, iters: int) -> int:
    """Call register() repeatedly; verify consistent immutability."""
    crashes = 0
    baseline = register()
    for i in range(iters):
        r = register()
        if r != baseline:
            print(f"  FAIL: register() changed between calls: {baseline} → {r}", file=sys.stderr)
            crashes += 1
            break
        if r is baseline:
            print(f"  INFO: register() returns the same dict object (not a copy — OK)", file=sys.stderr)
    return crashes


def run(iters: int, seed: int) -> int:
    import random
    rng = random.Random(seed)
    t0 = time.monotonic()

    print("  running register_api suite…")
    c1 = suite_register_api()
    print(f"    register_api: crashes={c1}")

    print("  running cli_register suite…")
    c2 = suite_cli_register()
    print(f"    cli_register: crashes={c2}")

    print("  running mask_constants suite…")
    c3 = suite_mask_constants()
    print(f"    mask_constants: crashes={c3}")

    print(f"  running register_fuzz ({iters} iters)…")
    c4 = suite_random_register_fuzz(rng, iters)
    print(f"    register_fuzz: crashes={c4}")

    dt = time.monotonic() - t0
    total = c1 + c2 + c3 + c4
    print(f"[register] iters={iters} crashes={total} time={dt:.2f}s")
    return 1 if total else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harness_register: verify register() API and --register CLI")
    ap.add_argument("--iters", type=int, default=MAX_ITERS)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    sys.exit(run(args.iters, args.seed))
