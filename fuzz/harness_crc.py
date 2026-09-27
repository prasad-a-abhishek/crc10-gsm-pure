#!/usr/bin/env python3
"""Surface-1 harness: crc(data) — Python API fuzzer (stdlib subprocess).

Fuzzes the single public function `crc10_gsm.crc(data)` by spawning a fresh
`python3 -c` subprocess for every iteration (the stdlib subprocess pattern
called out in the task body's "Python stdlib subprocess harnesses" guidance).
This isolates each invocation — a crash in the child never takes down the
harness, and per-input timing gives a clean lower bound on the cost of one
invocation.

Oracle strategy: every random byte sequence must produce a value in
[0, 1024) AND must match an independent reference implementation
(`_ref_crc`) bit-for-bit on the same input. Mismatch = bug.

Usage:
    python3 fuzz/harness_crc.py --iters 50000 --max-bytes 4096 --seed-corpus fuzz/corpus_seed

Outputs:
    fuzz/logs/crc_iterations.jsonl   — one JSON per iteration
    fuzz/logs/crc_summary.json       — totals + timings
    fuzz/crashes/crc_<hash>.bin     — any input that caused mismatch / hang / crash
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

WORKTREE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKTREE / "src"))


# Independent pure-Python reference (writes same algorithm with no module
# coupling — if crc10_gsm ever silently regresses, the oracle catches it).
def _ref_crc(data: bytes) -> int:
    MASK = 0x3FF
    POLY = 0x175
    XOROUT = 0x3FF
    crc_reg = 0x000
    for byte in data:
        crc_reg ^= (byte << 2) & MASK
        for _ in range(8):
            if crc_reg & 0x200:
                crc_reg = ((crc_reg << 1) ^ POLY) & MASK
            else:
                crc_reg = (crc_reg << 1) & MASK
    return (crc_reg ^ XOROUT) & MASK


# Stress shapes — the cycle_131 TEST_GAPS.md gap list condensed to generators.
STRESS_GENERATORS = {
    "single_byte_0":     lambda r: bytes([0x00]),
    "single_byte_1":     lambda r: bytes([0x01]),
    "single_byte_7f":    lambda r: bytes([0x7F]),
    "single_byte_80":    lambda r: bytes([0x80]),
    "single_byte_ff":    lambda r: bytes([0xFF]),
    "empty":             lambda r: b"",
    "two_bytes_same":    lambda r: bytes([r.randint(0, 255)] * 2),
    "two_bytes_diff":    lambda r: bytes([r.randint(0, 255), r.randint(0, 255)]),
    "all_zero_n":        lambda r: bytes(b"\x00" * r.randint(1, 4096)),
    "all_ff_n":          lambda r: bytes(b"\xff" * r.randint(1, 4096)),
    "alternating":       lambda r: bytes(((i & 1) * 0xFF) for i in range(r.randint(1, 4096))),
    "sweep_0_to_n":      lambda r: bytes((i & 0xFF) for i in range(r.randint(1, 4096))),
    "single_bit_walk":   lambda r: bytes((1 << (i % 8)) for i in range(r.randint(1, 256))),
    "random_short":      lambda r: bytes(r.randint(0, 255) for _ in range(r.randint(1, 64))),
    "random_long":       lambda r: bytes(r.randint(0, 255) for _ in range(r.randint(64, 4096))),
    "canonical_ac3":     lambda r: b"123456789",
    "ascii_text":        lambda r: ("the quick brown fox jumps over the lazy dog " * 20).encode()[:r.randint(1, 1024)],
    "high_entropy":      lambda r: bytes(r.getrandbits(8) for _ in range(r.randint(1, 2048))),
    "leading_ff":        lambda r: bytes([0xFF] * r.randint(1, 16)) + bytes(r.randint(0, 255) for _ in range(r.randint(1, 1024))),
    "trailing_ff":       lambda r: bytes(r.randint(0, 255) for _ in range(r.randint(1, 1024))) + bytes([0xFF] * r.randint(1, 16)),
    "random_1MiB":       lambda r: bytes(r.randint(0, 255) for _ in range(1024 * 1024)),
}


def run_child(payload: bytes, timeout: float) -> tuple[int, str, str, float]:
    """Spawn a child python process to compute crc(payload); return (rc, stdout, stderr, secs).

    Payload is passed via stdin (not argv) because embedding >2 KiB in -c
    triggers E2BIG on Linux. The child reads its own stdin into a hex string,
    converts to bytes, and prints the CRC integer.
    """
    encoded = payload.hex()
    # Child script — minimal, no imports from sys.path needed because we
    # prepend the src/ dir via PYTHONPATH env below.
    child = (
        "from crc10_gsm import crc\n"
        "import sys\n"
        "data = bytes.fromhex(sys.stdin.buffer.read().decode('ascii'))\n"
        "print(crc(data))\n"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(WORKTREE / "src") + os.pathsep + env.get("PYTHONPATH", "")
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["python3", "-c", child],
            input=encoded.encode("ascii"),
            capture_output=True,
            timeout=timeout,
            cwd=str(WORKTREE),
            env=env,
        )
        dt = time.perf_counter() - t0
        return proc.returncode, proc.stdout.decode().strip(), proc.stderr.decode().strip(), dt
    except subprocess.TimeoutExpired:
        dt = time.perf_counter() - t0
        return -1, "", f"TIMEOUT after {timeout}s", dt


def run_child_type_error(arg_repr: str, timeout: float) -> tuple[int, str, str, float]:
    """Spawn a child that evals `arg_repr` and passes the result to crc().

    This is the ONLY way to actually exercise the isinstance type guard —
    passing the value through stdin as bytes just produces bytes and
    never triggers the guard. The child wraps the eval in a try/except so
    TypeError becomes a clean rc=1 with the exception text on stderr.
    """
    child = (
        "from crc10_gsm import crc\n"
        f"arg = {arg_repr}\n"
        "try:\n"
        "    out = crc(arg)\n"
        "    print(out)\n"
        "except TypeError as e:\n"
        "    print('TYPEERROR:', e, file=__import__('sys').stderr)\n"
        "    raise SystemExit(1)\n"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(WORKTREE / "src") + os.pathsep + env.get("PYTHONPATH", "")
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["python3", "-c", child],
            capture_output=True,
            timeout=timeout,
            cwd=str(WORKTREE),
            env=env,
        )
        dt = time.perf_counter() - t0
        return proc.returncode, proc.stdout.decode().strip(), proc.stderr.decode().strip(), dt
    except subprocess.TimeoutExpired:
        dt = time.perf_counter() - t0
        return -1, "", f"TIMEOUT after {timeout}s", dt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iters", type=int, default=20000)
    parser.add_argument("--max-bytes", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=0xC510)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--corpus-dir", default="fuzz/corpus_seed")
    parser.add_argument("--log-dir", default="fuzz/logs")
    parser.add_argument("--crash-dir", default="fuzz/crashes")
    args = parser.parse_args()

    log_dir = WORKTREE / args.log_dir
    crash_dir = WORKTREE / args.crash_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    crash_dir.mkdir(parents=True, exist_ok=True)

    iterations_log = log_dir / "crc_iterations.jsonl"
    summary_log = log_dir / "crc_summary.json"

    rng = random.Random(args.seed)
    iter_records = []
    mismatches: list[dict] = []
    crashes: list[dict] = []
    timeouts: list[dict] = []
    type_errors: list[dict] = []

    # Type-error matrix (only for surface 1 — confirm isinstance guard works
    # for the full deny-list; this is not random). Each entry is a Python
    # expression the child evals and passes to crc().
    type_inputs = [
        ("None",        "None"),
        ("int",         "42"),
        ("str",         "'string'"),
        ("list",        "[1, 2, 3]"),
        ("dict",        "{'k': 1}"),
        ("float",       "3.14"),
        ("object",      "object()"),
        ("generator",   "(i for i in range(3))"),
        ("range",       "range(5)"),
        ("tuple",       "(1, 2, 3)"),
        ("set",         "{1, 2, 3}"),
        ("frozenset",   "frozenset({1, 2})"),
        ("iterator",    "iter([1, 2, 3])"),
        ("complex",     "1+2j"),
        ("bool",        "True"),
        ("bytes_already", "b'hello'"),  # should NOT raise — verify guard accepts
        ("bytearray_already", "bytearray(b'hello')"),
        ("memoryview_already", "memoryview(b'hello')"),
        ("two_args",        "(b'hello', 42)"),  # TypeError: takes 1 positional
        ("nested_bad",   "[[]]"),
    ]
    for label, expr in type_inputs:
        rc, out, err, dt = run_child_type_error(expr, args.timeout)
        iter_records.append({
            "iter": len(iter_records),
            "shape": f"type_error:{label}",
            "expr": expr,
            "rc": rc,
            "stdout": out,
            "stderr": err,
            "elapsed": dt,
        })
        # Acceptance rule for the deny-list: must raise TypeError (rc=1,
        # stderr contains "TYPEERROR:" or "TypeError:"). Acceptance rule for
        # the allow-list (bytes/bytearray/memoryview): must succeed (rc=0,
        # stdout is an int 0..1023). Everything else is a finding.
        if label in ("bytes_already", "bytearray_already", "memoryview_already"):
            if rc != 0 or not out.isdigit():
                type_errors.append({"input": label, "expr": expr, "rc": rc, "stdout": out, "stderr": err,
                                    "issue": "allow_list_rejected"})
        else:
            # Accept either "TypeError" (from crc()'s own raise) or our
            # child-script's marker "TYPEERROR:" as evidence the guard fired.
            guard_fired = (rc != 0) and ("TypeError" in err or "TYPEERROR" in err)
            if not guard_fired:
                type_errors.append({"input": label, "expr": expr, "rc": rc, "stdout": out, "stderr": err,
                                    "issue": "guard_did_not_reject"})

    # Random fuzz loop
    shapes = list(STRESS_GENERATORS.keys())
    t_total = time.perf_counter()
    for i in range(args.iters):
        shape = rng.choice(shapes)
        payload = STRESS_GENERATORS[shape](rng)
        rc, out, err, dt = run_child(payload, args.timeout)

        rec = {
            "iter": i,
            "shape": shape,
            "payload_len": len(payload),
            "rc": rc,
            "stdout": out[:200],
            "stderr": err[:200],
            "elapsed": dt,
        }
        iter_records.append(rec)

        if rc == -1:  # timeout
            timeouts.append({"iter": i, "shape": shape, "payload_len": len(payload), "payload_head": payload[:32].hex()})
        elif rc != 0:
            crashes.append({"iter": i, "shape": shape, "payload_len": len(payload), "rc": rc, "stderr": err[:500]})
        else:
            # Verify mask and oracle
            try:
                got = int(out, 10)
                expected = _ref_crc(payload)
                if got != expected:
                    mismatches.append({"iter": i, "shape": shape, "got": got, "expected": expected,
                                       "payload_head": payload[:32].hex()})
                elif not (0 <= got < 1024):
                    mismatches.append({"iter": i, "shape": shape, "got": got, "issue": "out_of_mask_range"})
            except ValueError:
                mismatches.append({"iter": i, "shape": shape, "issue": "non_integer_output", "stdout": out[:200]})

    total_secs = time.perf_counter() - t_total
    summary = {
        "harness": "harness_crc.py",
        "surface": "crc10_gsm.crc(data)",
        "iters": args.iters,
        "type_error_inputs": len(type_inputs),
        "type_errors_unexpected": len(type_errors),
        "mismatches": len(mismatches),
        "crashes": len(crashes),
        "timeouts": len(timeouts),
        "total_secs": round(total_secs, 3),
        "exec_per_sec": round((args.iters + len(type_inputs)) / total_secs, 2),
        "shape_distribution": {s: sum(1 for r in iter_records if r.get("shape") == s) for s in shapes},
        "mismatch_samples": mismatches[:5],
        "crash_samples": crashes[:5],
        "timeout_samples": timeouts[:5],
        "type_error_samples": type_errors[:5],
        "verdict": "PASS" if (not mismatches and not crashes and not timeouts and not type_errors) else "FAIL",
    }
    summary_log.write_text(json.dumps(summary, indent=2))

    with iterations_log.open("w") as fh:
        for r in iter_records:
            fh.write(json.dumps(r) + "\n")

    # Persist mismatches/crashes to fuzz/crashes/
    for kind, items in (("mismatch", mismatches), ("crash", crashes), ("timeout", timeouts)):
        for it in items:
            sha = hashlib.sha256(json.dumps(it, sort_keys=True).encode()).hexdigest()[:16]
            (crash_dir / f"{kind}_{sha}.json").write_text(json.dumps(it, indent=2))

    print(json.dumps(summary, indent=2))
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())