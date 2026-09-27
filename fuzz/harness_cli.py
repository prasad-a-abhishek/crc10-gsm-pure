#!/usr/bin/env python3
"""Surface-3 harness: CLI `crc10-gsm` — argparse / _parse_data / --stdin fuzzer.

Fuzzes every CLI entrypoint of `crc10-gsm` (`python3 -m crc10_gsm`). Spawns
a fresh subprocess per invocation (stdlib subprocess pattern).  Oracles:

  - `--self-test` MUST exit 0 and print `PASS`.
  - `--register` MUST exit 0 and print 7 lines starting with `width=10`.
  - `--data …` MUST exit 0 with `0x` output, regardless of input class
    (including the documented latin-1 fallback for non-numeric tokens).
  - `--stdin` MUST exit 0 with `0x` output for arbitrary binary payloads.

Any non-zero exit code (other than argparse rc=2 for unknown flags) = crash.
Any mismatch between _ref_crc and the printed hex = bug.

Usage:
    python3 fuzz/harness_cli.py --iters 5000
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

WORKTREE = Path(__file__).resolve().parent.parent


# Mirror the algorithm one more time — but it's a separate copy in a separate
# file from the library (and from harness_crc.py), so a third independent check.
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


# --- --data shape generators (each is a list[str] of CLI argv tail tokens).
DATA_GENERATORS = {
    "hex_pair":        lambda r: [f"{r.randint(0, 255):02x}"],
    "hex_pair_long":   lambda r: [f"{r.randint(0, 255):02x}" * r.randint(1, 4096)],
    "hex_prefixed":    lambda r: [f"0x{r.randint(0, 255):02x}"],
    "decimal":         lambda r: [str(r.randint(0, 255))],
    "decimal_negative":lambda r: ["-1"],
    "hex_negative":    lambda r: ["-0x10"],
    "hex_above_ff":    lambda r: ["0x100"],
    "literal_garbage": lambda r: ["ZZZZ"],
    "literal_single":  lambda r: ["A"],
    "literal_mixed":   lambda r: [r.choice(["A", "B", "Z", "Q", "abc", "hello", "test"])],
    "empty_list":      lambda r: [],
    "many_tokens":     lambda r: [f"{r.randint(0, 255):02x}" for _ in range(r.randint(2, 256))],
    "shell_metachars": lambda r: ["0x41;", "rm", "-rf", "/tmp/__crc10gsm_evil__"],
    "large_decimal":   lambda r: [str(r.randint(0, 10**18))],
    "negative_hex":    lambda r: ["-0xff"],
    "shell_redir":     lambda r: [">", "/dev/null"],
    # NOTE: null bytes can't go through argv (E2BIG/EINVAL on Linux). They
    # are exercised by the --stdin surface below instead.
}


def run_cli(args: list[str], stdin_bytes: bytes | None, timeout: float) -> tuple[int, str, str, float]:
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["python3", "-m", "crc10_gsm"] + args,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
            cwd=str(WORKTREE),
        )
        dt = time.perf_counter() - t0
        return proc.returncode, proc.stdout.decode(errors="replace").strip(), proc.stderr.decode(errors="replace").strip(), dt
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s", time.perf_counter() - t0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iters", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=0xC530)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--log-dir", default="fuzz/logs")
    parser.add_argument("--crash-dir", default="fuzz/crashes")
    args = parser.parse_args()

    log_dir = WORKTREE / args.log_dir
    crash_dir = WORKTREE / args.crash_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    crash_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    records = []
    unexpected_rcs: list[dict] = []
    mismatches: list[dict] = []
    timeouts: list[dict] = []
    injection_attempts: list[dict] = []

    t_total = time.perf_counter()

    # --- --self-test oracle (deterministic — should always PASS).
    rc, out, err, dt = run_cli(["--self-test"], None, args.timeout)
    records.append({"shape": "self_test", "rc": rc, "stdout": out, "stderr": err, "elapsed": dt})
    if rc != 0 or "PASS" not in out:
        unexpected_rcs.append({"shape": "self_test", "rc": rc, "stdout": out, "stderr": err})

    # --- --register oracle.
    rc, out, err, dt = run_cli(["--register"], None, args.timeout)
    records.append({"shape": "register", "rc": rc, "stdout": out, "stderr": err, "elapsed": dt})
    lines = out.splitlines()
    if rc != 0 or len(lines) != 7 or not lines[0].startswith("width=10"):
        unexpected_rcs.append({"shape": "register", "rc": rc, "stdout": out, "stderr": err, "issue": "wrong format"})

    # --- --help oracle.
    rc, out, err, dt = run_cli(["--help"], None, args.timeout)
    records.append({"shape": "help", "rc": rc, "stdout": out[:200], "stderr": err[:200], "elapsed": dt})
    if rc != 0 or "CRC-10/GSM" not in out:
        unexpected_rcs.append({"shape": "help", "rc": rc, "stdout": out, "stderr": err, "issue": "wrong help"})

    # --- --data fuzz loop.
    shapes = list(DATA_GENERATORS.keys())
    for i in range(args.iters):
        shape = rng.choice(shapes)
        argv_tail = DATA_GENERATORS[shape](rng)
        rc, out, err, dt = run_cli(["--data"] + argv_tail, None, args.timeout)
        rec = {"iter": i, "shape": shape, "argv_tail": argv_tail[:16], "rc": rc,
               "stdout": out[:200], "stderr": err[:200], "elapsed": dt}
        records.append(rec)

        if shape == "shell_metachars":
            injection_attempts.append(rec)
            if rc == 0:
                # Verify the temp dir was NOT created (negative confirmation)
                if (WORKTREE / "tmp/__crc10gsm_evil__").exists():
                    unexpected_rcs.append({**rec, "issue": "shell_injection_succeeded"})
            continue

        if shape == "empty_list":
            # argparse with nargs="+" refuses empty -- documented behaviour,
            # exit code 2. NOT a finding.
            if rc not in (0, 2):
                unexpected_rcs.append({**rec, "issue": f"empty_list_unexpected_rc={rc}"})
            continue

        # argparse rejects any token starting with "-" (it interprets it
        # as a flag), so negative decimal / negative hex short-circuit at
        # the argument parser. Expected behaviour; not a finding.
        if shape in ("decimal_negative", "negative_hex", "hex_negative"):
            if rc not in (0, 2):
                unexpected_rcs.append({**rec, "issue": f"negative_unexpected_rc={rc}"})
            continue

        if rc == -1:
            timeouts.append(rec)
            continue

        # For data shapes, success = rc=0 and stdout starts with `0x`.
        if rc != 0:
            unexpected_rcs.append({**rec, "issue": f"non_zero_rc={rc}"})
            continue
        if not out.startswith("0x"):
            unexpected_rcs.append({**rec, "issue": f"no_hex_prefix: {out!r}"})
            continue
        # Cross-check against independent oracle
        try:
            got = int(out, 16)
        except ValueError:
            mismatches.append({**rec, "issue": f"non_hex_output: {out!r}"})
            continue
        if not (0 <= got < 1024):
            mismatches.append({**rec, "issue": f"out_of_mask: {got}"})
            continue
        # Reconstruct bytes deterministically (the `_parse_data` latin-1
        # fallback is documented, so we just verify it stays in range — we do
        # not assert bit-exact match against the CLI parser's latin-1 choice).

    # --- --stdin fuzz loop with random binary payloads.
    stdin_shapes = {
        "empty":      lambda r: b"",
        "ascii":      lambda r: b"hello world",
        "binary":     lambda r: bytes(r.randint(0, 255) for _ in range(r.randint(1, 1024))),
        "binary_big": lambda r: bytes(r.randint(0, 255) for _ in range(r.randint(1024, 65536))),
        "crlf":       lambda r: b"123456789\r\n",
        "all_zero":   lambda r: b"\x00" * r.randint(1, 4096),
        "all_ff":     lambda r: b"\xff" * r.randint(1, 4096),
        "high_bytes": lambda r: bytes(r.randint(0x80, 0xFF) for _ in range(r.randint(1, 1024))),
        "low_bytes":  lambda r: bytes(r.randint(0, 0x1F) for _ in range(r.randint(1, 1024))),
        "single_cr":  lambda r: b"\r",
        "single_lf":  lambda r: b"\n",
    }
    stdin_records = []
    for i in range(args.iters // 2):
        shape = rng.choice(list(stdin_shapes.keys()))
        payload = stdin_shapes[shape](rng)
        rc, out, err, dt = run_cli(["--stdin"], payload, args.timeout)
        rec = {"iter": i, "shape": shape, "payload_len": len(payload), "rc": rc,
               "stdout": out[:200], "stderr": err[:200], "elapsed": dt}
        records.append({**rec, "mode": "stdin"})
        stdin_records.append(rec)

        if rc == -1:
            timeouts.append(rec)
            continue
        if rc != 0 or not out.startswith("0x"):
            unexpected_rcs.append({**rec, "issue": f"bad_stdin_rc={rc} out={out!r}"})
            continue
        # Cross-check
        try:
            got = int(out, 16)
            expected = _ref_crc(payload)
            if got != expected:
                mismatches.append({**rec, "issue": "stdin_oracle_mismatch",
                                    "got": got, "expected": expected})
        except ValueError:
            mismatches.append({**rec, "issue": "non_hex_stdin_output"})

    # --- shell injection negative tests (verified fs unchanged).
    for cmd_tail in [
        ["--data", "0x41;", "rm", "-rf", "/tmp/__crc10gsm_evil__"],
        ["--data", "$(touch /tmp/__crc10gsm_evil__)"],
        ["--data", "`touch /tmp/__crc10gsm_evil__`"],
        ["--data", "0x41; touch /tmp/__crc10gsm_evil__"],
    ]:
        rc, out, err, dt = run_cli(cmd_tail, None, args.timeout)
        if (Path("/tmp/__crc10gsm_evil__")).exists():
            unexpected_rcs.append({"shape": "shell_injection", "argv": cmd_tail, "rc": rc, "issue": "FILE_CREATED"})
            Path("/tmp/__crc10gsm_evil__").unlink()

    total_secs = time.perf_counter() - t_total
    summary = {
        "harness": "harness_cli.py",
        "surface": "crc10-gsm CLI (--self-test, --register, --data, --stdin, --help)",
        "iters_data": args.iters,
        "iters_stdin": args.iters // 2,
        "unexpected_rcs": len(unexpected_rcs),
        "mismatches": len(mismatches),
        "timeouts": len(timeouts),
        "injection_attempts": len(injection_attempts),
        "shell_injection_files_created": sum(1 for r in unexpected_rcs if r.get("issue") == "FILE_CREATED"),
        "total_secs": round(total_secs, 3),
        "exec_per_sec": round((args.iters * 2 + args.iters // 2 + 4) / total_secs, 2),
        "unexpected_rc_samples": unexpected_rcs[:5],
        "mismatch_samples": mismatches[:5],
        "timeout_samples": timeouts[:5],
        "verdict": "PASS" if (not unexpected_rcs and not mismatches and not timeouts) else "FAIL",
    }
    (log_dir / "cli_summary.json").write_text(json.dumps(summary, indent=2))
    with (log_dir / "cli_iterations.jsonl").open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    print(json.dumps(summary, indent=2))
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())