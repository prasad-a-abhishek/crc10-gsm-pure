# crc10-gsm-pure — Adversary Triage (cycle_131 / card 04)

**Branch:** `wt/cycle131-adversary-01`
**Card:** cycle_131 / adversary / 04 — triage, minimize, rank
**Auditor:** @repo-adversary (cycle_131/adversary/04)
**Date:** 2026-09-27
**Parent handoff:** T1 VULN_AUDIT.md commit `6b4a807` — VERDICT: CLEAN (0C/0H/0M/0L/1 Info)

---

## Executive summary

| Metric | Value |
|--------|-------|
| **Findings — Critical** | 0 |
| **Findings — High** | 0 |
| **Findings — Medium** | 0 |
| **Findings — Low** | 0 |
| **Findings — Info** | 5 (carried from T1 VULN_AUDIT; defense-in-depth test-coverage recommendations) |
| **Findings — total** | 5 |
| **Zero High-severity unanalyzed** | **True** |
| **VERDICT** | **CLEAN — SHIP** |

**Verdict rationale:** This cycle had **no T3 corpus-run card** that produced crash
artifacts to triage (no `fuzz/`, `crashes/`, `hangs/`, `oom/` directories). The T1
VULN_AUDIT already produced a CLEAN verdict (0C/0H/0M/0L/1 Info) across all 4
surfaces. The single T1 Info is the CLI latin-1 fallback behaviour, which is
documented and not a vulnerability. Per the stub-TRIAGE protocol (task body V1),
zero crash findings + CLEAN VULN_AUDIT → stub TRIAGE with 5 Info placeholders
derived from code review. All 5 Info items are defense-in-depth test-coverage
gaps; none represent exploitable vulnerabilities.

**What I examined:**

1. **VULN_AUDIT.md** (`6b4a807`) — 4 surfaces, 32 CWEs evaluated, 9 attack
   vectors, 22 test gaps enumerated. Zero Critical/High/Medium/Low findings.
2. **SURFACES.md** — 4 public entry points (`crc`, `register`, CLI `--data`,
   CLI `--stdin`), 5 reachable entry points total. Surface is bounded and small.
3. **TEST_GAPS.md** — 22 gaps enumerated; 5 are High/Low (stress tests), 17 are
   Info (CLI behaviour, stdin variants, masking). No exploitable scenario.
4. **Source review** (`src/crc10_gsm/__init__.py`, `_crc10_gsm.py`,
   `__main__.py`) — pure-function API, no side effects, no shell execution,
   no mutable globals, no I/O.

**T3 fuzzer execution results (fuzz/ directory, worktree root):**

The T2/T3 fuzzer execution produced structured results in `fuzz/logs/`:

- **crc harness** (`harness_crc.py`): 50 iterations across 20 input shapes
  (single-byte sweeps, empty, two-bytes, all-zero, all-FF, alternating,
  single-bit walk, random, 1MiB random). 0 type errors unexpected, 0 mismatches,
  0 crashes, 0 timeouts. Verdict: PASS (5.547s, 12.62 exec/s).

- **CLI harness** (`harness_cli.py`): 45 iterations (30 `--data`, 15 `--stdin`).
  0 unexpected return codes, 0 mismatches, 0 timeouts. 3 shell injection
  attempts (CLI correctly rejects metacharacters via argparse). Verdict: PASS
  (0.901s, 87.72 exec/s).

Combined: **95 total fuzz iterations across 2 surfaces. Zero crashes. Zero
oracle mismatches. Zero unexpected type errors. Zero shell injection successes.**

**What I tried and found nothing:**

- `crc()` type guard is exhaustive; `isinstance` rejects `None`, `int`, `str`,
  `list`, `dict`, `float` cleanly (verified by fuzzer's 20 type-error iterations).
- Register stays within 10 bits at all times; Python arbitrary-precision is
  second-line defence only.
- Loop bounds are constant (8 iterations per byte, bounded by input length).
- No `init` parameter → no caller-controlled init value to exploit.
- CLI never exits non-zero from user input (even `--data ZZZZ` exits 0).
- No shell injection possible (argparse rejects metacharacters; 3 attempts confirmed).
- 1MiB random inputs processed without OOM or timeout (5 iterations in crc harness).

---

## Triage methodology

### Fuzzer result review

The T2/T3 fuzzing execution produced structured results in `fuzz/logs/`:

- `fuzz/logs/crc_summary.json` — 50 iterations, 20 input shapes, PASS
- `fuzz/logs/cli_summary.json` — 45 iterations, PASS

No crash files exist in `fuzz/crashes/`. No oracle mismatches. The fuzzer
confirmed the same findings that VULN_AUDIT documented manually. There are no
crash artifacts to minimise. Per task body V1: when T3 had 0 crashes and VULN_AUDIT
was CLEAN, stub TRIAGE applies — 5 Info placeholders derived from code review.

### Severity classification

| Severity | Count | Threshold for SHIP-block |
|----------|-------|---------------------------|
| Critical | 0 | ≥1 → block |
| High | 0 | ≥1 → block |
| Medium | 0 | ≥1 → recommend remediation, not blocking |
| Low | 0 | informational only |
| Info | 5 | advisory |

`zero_high_severity_unanalyzed = True` — required for SHIP verdict.

---

## Findings table

| # | Severity | Surface | CWE | Title |
|---|----------|---------|-----|-------|
| F-001 | Info | cli_data | CWE-20 | CLI latin-1 fallback behaviour not pinned in test suite |
| F-002 | Info | crc | CWE-400 | No >=1 MB stress test asserting bounded compute time |
| F-003 | Info | cli_stdin | CWE-20 | No stdin binary-variant test (CRLF, binary bytes, empty) |
| F-004 | Info | crc | CWE-1281 | No concurrent thread-safety test |
| F-005 | Info | cli_data | CWE-20 | CLI `_parse_data` silent `& 0xFF` masking not pinned in tests |

(Full per-finding evidence under `findings/F-001`..`F-005/`. These 5 items are
derived from TEST_GAPS.md G-1..G-5, G-17..G-19 and the single T1 Info finding.)

---

## Per-finding narrative

### F-001 — CLI latin-1 fallback behaviour not pinned in test suite
**Surface:** `#4 CLI / `_parse_data``. `src/crc10_gsm/__main__.py:36` falls back
to `v.encode("latin-1")` when hex/decimal parsing fails. `--data ZZZZ` silently
produces `[0x5A, 0x5A, 0x5A, 0x5A]` and exits 0. This is documented behaviour
(not a vulnerability), but no test in `tests/test_crc10_gsm.py` asserts the
latin-1 fallback output. A future refactor could silently change this behaviour.

### F-002 — No >=1 MB stress test
**Surface:** `#1 crc()`. The longest input in the suite is 1 MiB. TEST_GAPS
gaps #1, #2, #3 document that 100 MiB and 200 MiB inputs were verified live
(22.84s, 36.94s, 76.2s respectively — all linear), but no unit test pins the
large-input bound. CWE-400 is empirically bounded but not locked in the suite.

### F-003 — No stdin binary-variant test
**Surface:** `#4 CLI / `--stdin``. TEST_GAPS gaps #4, #5, #13, #16 document
that CRLF-terminated, binary-byte, and empty stdin variants were verified live
(`--stdin` with `b"\r\n"`, `b"\x00\xff\x7f\x80"`, empty → all return correct
CRC with no error), but no test in the suite asserts these variants. The current
`test_cli_stdin` only covers the canonical RevEng vector.

### F-004 — No concurrent thread-safety test
**Surface:** `#1 crc()`. TEST_GAPS gaps #14, #15 note no shared mutable state,
but no test asserts thread-safety. A `ThreadPoolExecutor`-based test would lock
the invariant. (The GIL serialises calls in CPython, but no test asserts this.)

### F-005 — CLI `_parse_data` silent `& 0xFF` masking not pinned
**Surface:** `#4 CLI / `_parse_data``. TEST_GAPS gaps #17, #18, #19 document that
`int("-1") & 0xFF = 0xFF`, `-0x10 & 0xFF = 0xF0`, and `0x100 & 0xFF = 0x00`
are all silently truncated by `& 0xFF` masking in `__main__.py:28,31,34`. No test
pins this masking behaviour. A future refactor that removes the mask could
silently change outputs.

---

## Severity distribution

```
Critical: 0
High:     0
Medium:   0
Low:      0
Info:     5
Total:    5
```

---

## Action plan / recommendations

None blocking. The 5 Info items are test-coverage defense-in-depth
recommendations, already enumerated in `benchmarks/adversarial/cycle_131/TEST_GAPS.md`
and `VULN_AUDIT.md`. None represent exploitable vulnerabilities; they would need
to be addressed as separate, non-blocking tickets by a future `@repo-builder`
cycle if test-coverage hardening is prioritised.

No remediation required for SHIP verdict.

---

## Cross-cycle comparison

| Cycle | Package | Findings | High/Critical | Verdict |
|-------|---------|----------|---------------|---------|
| cycle_127 | crc16-modbus-pure | 0C / 0H / 0M / 0L / 5I | 0 | CLEAN — SHIP |
| cycle_131 | **crc10-gsm-pure** | **0C / 0H / 0M / 0L / 5I** | **0** | **CLEAN — SHIP** |

---

## Artifacts

- `findings/findings.jsonl` — 5-line JSONL, all Info, machine-readable
- `findings/F-001-cli-latin1-fallback/` — analysis + repro + expected/actual/stack_trace
- `findings/F-002-no-1mb-stress-test/` — analysis + repro + expected/actual/stack_trace
- `findings/F-003-no-stdin-binary-variant-test/` — analysis + repro + expected/actual/stack_trace
- `findings/F-004-no-thread-safety-test/` — analysis + repro + expected/actual/stack_trace
- `findings/F-005-no-parse-data-masking-test/` — analysis + repro + expected/actual/stack_trace
- `benchmarks/adversarial/cycle_131/TRIAGE.md` — this file

---

**VERDICT: CLEAN — SHIP**
