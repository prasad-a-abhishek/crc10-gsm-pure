# QA Report — crc10-gsm-pure (cycle_131)

tests_passing: true

## 1. README audit (Invariant 16)

README.md is 3506 bytes, 6 `## ` sections in canonical order:

| # | Heading | Line | Invariant 16 position |
|---|---|---|---|
| 1 | `## Quick Start` | 8 | ✓ (1st body section after Title/Badges) |
| 2 | `## ⚡ Performance & Benchmarks` | 24 | ✓ (immediately after Quick Start — Invariant 16 §3) |
| 3 | `## Why crc10-gsm?` | 44 | ✓ |
| 4 | `## Key Features` | 61 | ✓ |
| 5 | `## Limitations` | 94 | (extra section, §8.4 spec requirement) |
| 6 | `## License` | 101 | ✓ (last) |

- Install cmd: `pip install git+https://github.com/prasad-a-abhishek/crc10-gsm-pure.git` (line 11) — matches Invariant 24 (repo NOT on PyPI).
- Benchmarks section is at position #2, immediately after Quick Start — matches Invariant 16 §3.
- Three limitations in `## Limitations` (line 94): pure-Python reference / single-algorithm / not constant-time — matches §8.4 spec invariant.
- `grep -c '^## ' README.md` = 6 ✓.

## 2. AC regression (12 LOCKED ACs from SPEC.md §3)

All 12 LOCKED acceptance criteria verified live via `PYTHONPATH=src python3`:

| AC | Criterion | Expected | Actual | Status |
|---|---|---|---|---|
| AC1 | `crc(bytes([0x00])) == 0x3FF` | 0x3FF | 0x3FF | PASS |
| AC2 | `crc(b"") == 0x3FF` | 0x3FF | 0x3FF | PASS |
| AC3 | `crc(b"123456789") == 0x12A` (RevEng) | 0x12A | 0x12A | PASS |
| AC4 | `crc(bytes(range(10))) == 0x150` | 0x150 | 0x150 | PASS |
| AC5 | `crc(bytes([0x01])) == 0x28A` | 0x28A | 0x28A | PASS |
| AC6 | `crc(bytes([0xFF])) == 0x274` | 0x274 | 0x274 | PASS |
| AC7 | determinism on 1024-byte random input (x2 == same) | equal | 0x345 == 0x345 | PASS |
| AC8 | oracle differential vs `crcmod.mkCrcFun(0x175, …)` ≥100 inputs (in test suite, `test_oracle_*`) | match | covered by `test_oracle_independent_reference` ×50 + `test_oracle_set_deterministic`/`dedup` (parametrized from `_ORACLE_SET`) | PASS |
| AC9 | `crc(b"")` returns int, no raise | int | 0x3FF (int) | PASS |
| AC10 | `crc(None)`, `crc(123)`, `crc("hello")` raise `TypeError` with `bytes` in message | TypeError | all 3 raise TypeError; messages contain `bytes` | PASS |
| AC11 | result masked to 10 bits (`0 <= r < 1024`) always | always | 100/100 random samples in range | PASS |
| AC12 | 1MiB random input completes in <2s (no quadratic blowup) | <2s | 0.360s | PASS |

12/12 LOCKED ACs PASS.

## 3. Full pytest

```
$ PYTHONPATH=src pytest -q
........................................................................ [  6%]
... (1090 dots) ...
..........                                                               [100%]
1090 passed in 0.79s
```

- Collected: **1090** (`pytest --collect-only -q` → `tests/test_crc10_gsm.py: 1090`)
- Passed: **1090**
- Failed: **0**
- Exit code: 0
- File: `tests/test_crc10_gsm.py` (375 LOC, 35 test functions heavily parametrized)

≥100 test floor enforced; actual is 10.9× the floor.

## 4. Fresh-venv smoke (Honest pillar)

```
$ python3 -m venv /tmp/crc10-gsm-pure-smoke-57704
$ /tmp/crc10-gsm-pure-smoke-57704/bin/pip install -q /root/projects/crc10-gsm-pure/.worktrees/t_cycle131-build
$ /tmp/crc10-gsm-pure-smoke-57704/bin/crc10-gsm --self-test
PASS: crc(b'123456789') = 0x12A
$ /tmp/crc10-gsm-pure-smoke-57704/bin/python -c "from crc10_gsm import crc; print(hex(crc(b'123456789')))"
0x12a
$ rm -rf /tmp/crc10-gsm-pure-smoke-57704
```

- Install: clean, zero compilation, zero 3rd-party deps installed (only `crc10-gsm` itself).
- CLI smoke (`crc10-gsm --self-test`): PASS.
- Byte-exact check `crc(b'123456789') = 0x12a`: confirmed.
- Smoke venv removed cleanly.

CLI additional modes verified at worktree:
- `python3 -m crc10_gsm --data 31 32 33 34 35 36 37 38 39` → `0x12a`
- `python3 -m crc10_gsm --register` → `width=10 poly=373 init=0 refin=False refout=False xorout=1023 check=298`
- `echo -n "123456789" | python3 -m crc10_gsm --stdin` → `0x12a`
- `echo -n "" | python3 -m crc10_gsm --stdin` → `0x3ff`

## 5. Fuzz / boundary (≥3 inputs from standard list)

| # | Input | Result | Status |
|---|---|---|---|
| 1 | `b""` (empty) | 0x3FF (matches AC2 — init=0 + xorout=0x3FF) | PASS |
| 2 | 1MiB random bytes (seed=42) | 0x365, 0.359s, x2 determinism holds | PASS (AC7+AC12) |
| 3 | `b"\xff" * 1000` | 0x07C, in [0, 1024) | PASS |
| 4 | high bytes `bytes([0x80, 0x81, 0xfe, 0xff])` | 0x1B3, no crash | PASS |
| 5 | `crc(123)` | TypeError "crc10_gsm.crc() expected bytes-like, got int" | PASS (AC10) |
| 6 | `crc(None)` | TypeError with `bytes` in msg | PASS (AC10) |
| 7 | `crc("hello")` | TypeError with `bytes` in msg | PASS (AC10) |
| 8 | 50 random inputs of length 1..500 | all results in [0, 1024) | PASS (AC11) |
| 9 | `crc(bytearray(b'123456789'))` and `crc(memoryview(b'123456789'))` | both 0x12A | PASS (API parity) |

9/9 fuzz inputs PASS. 1MiB completes in 0.359s — well under 2s AC12 ceiling.

## 6. Secret scan

```
$ git grep -nE 'ghp_|pypi-AgEI|sk-|AKIA|BEGIN PRIVATE KEY' -- ':!*.lock'
(no matches)
```

**CLEAN** — zero hits across all tracked files.

## 7. Dependencies audit

```
$ cat pyproject.toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "crc10-gsm"
version = "0.1.0"
description = "Pure-Python reference implementation of CRC-10/GSM (3GPP TS 44.006), zero runtime deps."
readme = "README.md"
requires-python = ">=3.10"
dependencies = []
...
```

- `dependencies = []` (line 11) ✓ — zero runtime deps.
- Only build-time dep is `setuptools>=61.0` (PEP 517 build backend).
- `[project.optional-dependencies]` not present; only `pytest` used at test time (dev-only, not a runtime dep).

## 8. Cross-cycle oracle

CRC-10/GSM (this repo, cycle_131) vs CRC-10/ATM (cycle_114 shipped, poly=0x233, xorout=0x000) — distinct algorithms despite same width=10:

| Input | crc10-gsm (0x175 + xorout 0x3FF) | crc10-atm (0x233 + xorout 0x000) | Distinct? |
|---|---|---|---|
| `b""` | 0x3FF | 0x000 | YES |
| `b"\x00"` | 0x3FF | 0x000 | YES |
| `b"\xff"` | 0x274 | 0x0E1 | YES |
| `b"123456789"` | 0x12A | 0x199 | YES |
| `bytes(range(10))` | 0x150 | 0x2FC | YES |
| `b"\x00"*100` | 0x3FF | 0x000 | YES |
| `b"\xff"*100` | 0x01F | 0x033 | YES |

- CRC-10/GSM register: `{width: 10, poly: 0x175, init: 0x000, refin: False, refout: False, xorout: 0x3FF, check: 0x12A}`
- CRC-10/ATM parameters (from `/root/projects/crc10-atm-pure/src/crc10_atm_pure/__init__.py`): `poly=0x233, init=0x000, refin=False, refout=False, xorout=0x000`

**Cross-cycle disambiguation confirmed** — different polynomial AND different xorout; on every test input the two algorithms produce different CRC values. No collision.

## Summary

All 8 mandatory QA checks PASS for crc10-gsm-pure at commit cc478715c9f353634928c8ce464903ae6834f895 (branch wt/cycle131-build). The implementation is byte-exact against the RevEng canonical `0x12A` for ASCII `"123456789"` (AC3) and matches all 12 LOCKED ACs from SPEC.md §3, including the no-quadratic-blowup AC12 (1MiB in 0.359s, well under 2s ceiling) and 100-sample 10-bit mask enforcement (AC11). The pytest suite collects 1090 items (10.9× the QA floor of 100) and reports 1090 passed / 0 failed / exit 0 in 0.79s. The README follows Invariant 16's 6-section canonical order (Quick Start → Performance → Why → Key Features → Limitations → License) with the honest install command `pip install git+https://github.com/prasad-a-abhishek/crc10-gsm-pure.git` (repo not on PyPI per Invariant 24). A fresh-venv smoke at `/tmp/crc10-gsm-pure-smoke-57704` confirmed the package installs cleanly with zero runtime deps and `crc10-gsm --self-test` exits 0 with `PASS: crc(b'123456789') = 0x12A`. Secret-scan is CLEAN. Cross-cycle oracle vs crc10-atm-pure (cycle_114) confirms the two algorithms produce distinct values on every test input — no risk of aliasing. CLI works in all four modes (`--self-test`, `--data`, `--register`, `--stdin`). Useful + Proven + Honest pillars all satisfied.

VERDICT: SHIP