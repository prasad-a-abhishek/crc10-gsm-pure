# crc10-gsm-pure — Adversarial Harness Index (cycle_131/adversary/02)

> **Scope:** 6 standalone Python fuzz harnesses targeting the 4 surfaces
> enumerated in `SURFACES.md` (cycle_131/adversary/01).
> **Method:** stdlib-only fuzzing (`random`, `subprocess`, `argparse`, `time`).
> No Atheris / libFuzzer — pure-Python CRC is more efficiently tested with
> stdlib Python + oracle checks.
> **Date:** 2026-09-27
> **Commit:** see kanban metadata; this file is part of the same commit as the harnesses.

---

## Harness summary

| # | Harness | Surfaces covered | Mode | Smoke `--iters 100` | Notes |
|---|---------|-----------------|------|---------------------|-------|
| 1 | `harness_crc_main.py` | #1 (crc core API) | random+stress+canonical | 0 crashes / 1.30s | RevEng canonical vectors + 1 KiB stress patterns + random fuzz; asserts 10-bit range |
| 2 | `harness_type_errors.py` | #1 (type-error path) | curated+random | 0 crashes / 0.00s | 15-type curated negative suite; asserts TypeError (not ValueError) on non-bytes; random fuzz to find unexpected holes |
| 3 | `harness_cli_data.py` | #2 (CLI --data) | canonical+malformed+CRLF+fuzz | 0 crashes / 2.07s | Exercises all 3 _parse_data() tiers including latin-1 fallback; random hex-string fuzz |
| 4 | `harness_cli_stdin.py` | #3 (CLI --stdin) | empty+small+CRLF+large+fuzz | 0 crashes / 2.17s | Raw byte stdin; empty/1B/1KiB; CRLF; null bytes; large patterns |
| 5 | `harness_register.py` | #4 (register API / --register) | api+cli+constants+fuzz | 0 crashes / 0.02s | 7-field dict correctness; CLI parity; _MASK/_POLY/_XOROUT consistency |
| 6 | `harness_cross_cycle.py` | #1 (determinism + cross-cycle oracle) | determinism+oracle | 0 findings / 0.00s | 1000-repeat determinism on `b"123456789"`; cross-cycle vs crc10-atm-pure (SKIP if not installed); RevEng canonical only |

**Total surfaces covered:** 4 of 4 (SURFACES.md #1–#4).
**Total harnesses:** 6 (above the 3-harness minimum per Invariant 26 §2).

---

## Smoke results (`--iters 100` for every harness)

```
=== harness_crc_main ===     [crc_main]       iters=100  crashes=0  time=1.30s  exit=0
=== harness_type_errors ===  [type_errors]     iters=100  crashes=0  time=0.00s  exit=0
=== harness_cli_data ===     [cli_data]       iters=100  crashes=0  time=2.07s  exit=0
=== harness_cli_stdin ===    [cli_stdin]      iters=100  crashes=0  time=2.17s  exit=0
=== harness_register ===     [register]       iters=100  crashes=0  time=0.02s  exit=0
=== harness_cross_cycle ===  [cross_cycle]    iters=100  det_iters=1000 findings=0 atm_available=False time=0.00s  exit=0
```

All harnesses exit 0; zero crashes; zero findings.

---

## Per-harness detail

### 1. `harness_crc_main.py` (surface #1 — core CRC API)

Three sub-modes:
- **canonical**: 7 vectors — 2 RevEng-known answers (empty=0x3FF, `b"123456789"`=0x12A) plus 5 computed (single-byte, text, multi-byte) used only for range and no-crash checks.
- **stress**: 4 KiB blocks of all-0x00, all-0xFF, sequential 0..255, alternating 0x55 — all at 1 KiB and 4 KiB. Asserts 10-bit range and no exception.
- **random**: 100 iterations of length 0..64 KiB random bytes. Asserts result is `int` in `[0, 0x3FF]`.

### 2. `harness_type_errors.py` (surface #1 — type-error boundary)

Three sub-suites:
- **curated negative**: 15 non-bytes types (`None`, `int`, `str`, `list`, `dict`, `float`, `bool`, `tuple`, `set`, `complex`, `object()`) — each MUST raise `TypeError` with message containing `"expected bytes-like"`. NOT `ValueError`, NOT uncaught.
- **accept path**: `bytes`, `bytearray`, `memoryview` at 6 inputs — each MUST NOT raise and MUST return `int` in range.
- **random fuzz**: 100 random non-bytes objects drawn from a fixed pool — same TypeError assertion.

### 3. `harness_cli_data.py` (surface #2 — `--data` CLI flag)

Four sub-suites:
- **canonical**: RevEng hex strings + separate-arg forms — all must exit 0 with valid hex output.
- **malformed**: odd-length hex, non-hex strings (`ZZZZ` → latin-1 fallback), `0x` prefixes, decimal args, whitespace-tolerance — none may produce a Python Traceback.
- **CRLF/unicode**: CRLF in hex strings, em-dash unicode after hex — no Traceback.
- **random fuzz**: 100 random even-length hex strings — all must exit 0 with valid 4-digit hex output.

### 4. `harness_cli_stdin.py` (surface #3 — `--stdin` CLI flag)

Five sub-suites:
- **empty_and_small**: empty, single null, single 0xFF, single ASCII, 9-byte canonical, mixed small bytes.
- **CRLF/binary**: CRLF only, text+CRLF, multi-line CRLF, null interleaving, high-bit bytes, UTF-8 lead bytes, BOM-like bytes.
- **large_inputs**: 1 KiB and 4 KiB blocks of all-0x00, all-0xFF, sequential, alternating — all must exit 0 with valid hex.
- **random fuzz**: 100 random byte payloads up to 4 KiB.

### 5. `harness_register.py` (surface #4 — `register()` API + `--register` CLI)

Four sub-suites:
- **register_api**: verifies the returned dict has exactly 7 keys (`width`, `poly`, `init`, `refin`, `refout`, `xorout`, `check`) with correct values.
- **cli_register**: `crc10-gsm --register` exits 0 and prints all 7 `k=v` lines matching the Python dict.
- **mask_constants**: `_MASK == 0x3FF`, `_POLY == 0x175`, `_XOROUT == 0x3FF`; `_MASK == 2**width - 1`.
- **register_fuzz**: 100 repeat calls — all must return identical dict (function is deterministic).

### 6. `harness_cross_cycle.py` (surface #1 — determinism + cross-cycle oracle)

Three sub-suites:
- **determinism oracle**: 1000 repeat calls of `crc(b"123456789")` — all must return identical `int` (0x12A). Any divergence is a non-determinism bug.
- **cross-cycle oracle**: if `crc10-atm-pure` (cycle_114) is importable, runs 100 random inputs comparing `crc10_gsm` vs `crc10_atm`. The two algorithms MUST produce different outputs on the same input — a collision is a finding. If not installed → SKIP with exit 0 (graceful).
- **known-answer**: RevEng catalogue entries only (empty=0x3FF, `b"123456789"`=0x12A).

---

## Output format

Every harness accepts `--iters N` (default 100) and prints one summary line:

```
[<surface>] iters=N crashes=N time=Ts
```

Exit code 0 = success, 1 = any crash or finding.

Detailed results per surface saved to `fuzz/<surface>/results.json`.

---

## Running

```bash
# Smoke (100 iters each — fast, ~6 seconds total)
python3 benchmarks/adversarial/cycle_131/harness_crc_main.py --iters 100
python3 benchmarks/adversarial/cycle_131/harness_type_errors.py --iters 100
python3 benchmarks/adversarial/cycle_131/harness_cli_data.py --iters 100
python3 benchmarks/adversarial/cycle_131/harness_cli_stdin.py --iters 100 --max-kb 1
python3 benchmarks/adversarial/cycle_131/harness_register.py --iters 100
python3 benchmarks/adversarial/cycle_131/harness_cross_cycle.py --iters 100 --det-iters 1000

# Cross-cycle with oracle (install crc10-atm-pure first)
pip install /root/projects/crc10-atm-pure
python3 benchmarks/adversarial/cycle_131/harness_cross_cycle.py --iters 1000 --det-iters 1000

# Large stdin stress (up to 4 KiB per payload; increase --max-kb for larger)
python3 benchmarks/adversarial/cycle_131/harness_cli_stdin.py --iters 100 --max-kb 4
```

---

## Coverage matrix (surface × harness)

| Surface | crc_main | type_errors | cli_data | cli_stdin | register | cross_cycle |
|---------|----------|-------------|----------|-----------|----------|-------------|
| #1 `crc(data)` | ✓ | ✓ | — | — | — | ✓ |
| #1 type-error path | — | ✓ | — | — | — | — |
| #2 `--data` CLI | — | — | ✓ | — | — | — |
| #3 `--stdin` CLI | — | — | — | ✓ | — | — |
| #4 `register()` / `--register` | — | — | — | — | ✓ | — |

All 4 surfaces are touched by at least one harness.

---

## VERDICT

All 6 harnesses execute cleanly under `--iters 100`. Zero crashes, zero findings across 600+ fuzz inputs plus 1000-repeat determinism on `b"123456789"`. The package is fuzz-clean under this harness suite.

**VERDICT: CLEAN (cycle_131/adversary/02).**
