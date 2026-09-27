# CWE_MAP — crc10-gsm-pure (cycle_131)

> CWE mapping for the T1 VULN_AUDIT. For each candidate CWE we state
> whether it applies, where, and why / why-not. The verdict column
> ("applies") drives the per-finding severity in `VULN_AUDIT.md`.

## CWE-20 — Improper Input Validation

| Aspect | Detail |
|---|---|
| Applies? | **No** (positive evidence). |
| Where? | `src/crc10_gsm/_crc10_gsm.py:19-22` — explicit `isinstance` guard. |
| Evidence | `crc(None)`, `crc(123)`, `crc("hello")`, `crc([1,2,3])`, `crc({"a":1})`, `crc(3.14)` all raise `TypeError` with `bytes` in message (tested in `tests/test_crc10_gsm.py:91-119`). |
| Why-not | The function REJECTS every non-bytes-like input before entering the algorithm. AC10 (LOCKED). |

## CWE-125 — Out-of-bounds Read

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Where? | N/A — Python `bytes` indexing cannot go out-of-bounds (raises `IndexError`); the loop simply iterates `for byte in data` which bounds-checks each step. |
| Why-not | No `data[N]` direct indexing in the hot path; iteration is bounded by Python's runtime. |

## CWE-190 — Integer Overflow or Wraparound

| Aspect | Detail |
|---|---|
| Applies? | **No** (N/A in Python). |
| Where? | `_crc10_gsm.py:23-31` — internal register arithmetic. |
| Why-not | Python ints are arbitrary precision. The loop explicitly applies `& _MASK` (= 0x3FF) on every update and on the final result, guaranteeing the register never escapes 10 bits. CWE-190 is a C/C++ concept; in CPython it cannot materialise. |

## CWE-193 — Off-by-one Error

| Aspect | Detail |
|---|---|
| Applies? | **No** (verified). |
| Where? | `_crc10_gsm.py:26` — `for _ in range(8)` bit-fold loop. |
| Evidence | `crc(b"123456789") == 0x12A` (AC3) byte-exact against the RevEng canonical. The 8 iterations match the 8 bits per byte. Off-by-one would produce a non-canonical CRC. |
| Why-not | Differential test suite (50 random inputs vs independent reference, plus 30 deterministic oracles) catches off-by-one. |

## CWE-400 — Uncontrolled Resource Consumption

| Aspect | Detail |
|---|---|
| Applies? | **Partially** — documented, no exploitable bug, INFO-level only. |
| Where? | CLI `--stdin` path: `sys.stdin.buffer.read()` (line 70 of `__main__.py`). |
| Evidence | Probed at this audit: 100 MiB → 36.5s, 1 GiB → timed out at 60s, process would consume ~6 min linear time. No quadratic blowup. |
| Why-not | (a) The algorithm is O(n) per byte — linear, not quadratic. AC12 (LOCKED) requires <2s for 1MiB; measured 0.36s. (b) `--stdin` is opt-in: the caller must pipe bytes into the process. (c) No SIGPIPE / OOM observed in 100 MiB run. (d) No fix recommended: the library does not accept a "max bytes" parameter; documenting the linear cost is sufficient. |

## CWE-401 — Missing Release of Resource (Memory Leak)

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | Pure-Python function with no long-lived allocations. Local `crc_reg` is a single int; `for byte in data` releases the iterator frame on return. GC handles the rest. |

## CWE-404 — Improper Resource Shutdown

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | No file handles, sockets, locks, or subprocesses opened. |

## CWE-405 — Asymmetric Resource Consumption (Amplification)

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | The function is purely linear in input size. There is no super-linear branch (e.g. no regexp, no recursive expansion, no allocation amplification). |

## CWE-407 — Inefficient Algorithmic Complexity

| Aspect | Detail |
|---|---|
| Applies? | **No** (verified linear). |
| Where? | `_crc10_gsm.py:24-30` — outer × inner loop = 8n iterations over n bytes. |
| Evidence | Measured: 10KB → 3.6ms, 100KB → 36ms, 1MB → 359ms, 100MB → 35.4s. Ratio is flat at ~0.36 s/MiB. AC12 LOCKED. |

## CWE-476 — NULL Pointer Dereference

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Evidence | `crc(None)` raises `TypeError` (AC10), not `AttributeError`. Probed. |

## CWE-681 — Incorrect Conversion between Numeric Types

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Where? | CLI `_parse_data` line 31 / 34: `int(v, 16) & 0xFF` and `int(v) & 0xFF`. |
| Evidence | Explicit `& 0xFF` mask on every int-from-string path. The CLI never lets an unbounded int reach the algorithm. |

## CWE-770 — Allocation of Resources Without Limits or Throttling

| Aspect | Detail |
|---|---|
| Applies? | **Partially** — same as CWE-400. INFO-level, documented. |
| See | CWE-400 above. The library accepts arbitrary-length bytes; the CLI `--stdin` reads all of stdin into memory. This is the standard CLI contract for filter-style tools (`cat`, `md5sum`, `sha256sum`). |

## CWE-772 — Missing Release of Effective Resource

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | Same as CWE-401. |

## CWE-783 — Operator Precedence Logic Error

| Aspect | Detail |
|---|---|
| Applies? | **No** (verified). |
| Where? | `_crc10_gsm.py:25` — `crc_reg ^= (byte << 2) & _MASK` — parentheses correct. |
| Evidence | Byte-exact match against RevEng check value 0x12A. |

## CWE-835 — Loop with Unreachable Exit Condition ('Infinite Loop')

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Where? | `_crc10_gsm.py:24` outer + `:26` inner — both `for ... in` over finite iterables. |
| Why-not | No `while True`, no recursive structure, no condition that can fail to terminate. Probed 100 MB input — completed in 35.4s. |

## CWE-908 — Use of Uninitialized Resource

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Where? | `_crc10_gsm.py:23` — `crc_reg = 0x000` is an explicit initializer. |
| Why-not | Register is always set before use. |

## CWE-1284 — Improper Validation of Specified Quantity in Input

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | Function takes one argument (bytes-like) of arbitrary length; the only "quantity" is length, which has no upper bound and is not validated. This is correct — a CRC of length-N bytes is well-defined for all N ≥ 0. |

## CWE-1333 — Inefficient Regular Expression Complexity (ReDoS)

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | No regex anywhere in the codebase. |

## CWE-1357 — Reliance on Insufficiently Trustworthy Component

| Aspect | Detail |
|---|---|
| Applies? | **No**. |
| Why-not | `dependencies = []` (pyproject.toml:11). Zero runtime dependencies. No third-party trust boundary. |

## Summary

| CWE | Applies? | Severity if any |
|---|---|---|
| CWE-20 improper input validation | No | — |
| CWE-125 OOB read | No | — |
| CWE-190 integer overflow | No (N/A in Python) | — |
| CWE-193 off-by-one | No (verified) | — |
| CWE-400 resource consumption | Partial | Info |
| CWE-401 memory leak | No | — |
| CWE-404 improper shutdown | No | — |
| CWE-405 amplification | No | — |
| CWE-407 algorithmic complexity | No (linear) | — |
| CWE-476 NULL deref | No | — |
| CWE-681 numeric conversion | No (masked) | — |
| CWE-770 unbounded allocation | Partial (=CWE-400) | Info |
| CWE-772 missing release | No | — |
| CWE-783 operator precedence | No (verified) | — |
| CWE-835 infinite loop | No | — |
| CWE-908 uninitialized resource | No | — |
| CWE-1284 quantity validation | No | — |
| CWE-1333 ReDoS | No (no regex) | — |
| CWE-1357 untrustworthy component | No (zero deps) | — |

**Total CWEs considered: 19**
**CWEs that apply (any severity): 2** (both are the same Info-level
"no max-bytes limit on stdin" finding — CWE-400 and CWE-770 are
mathematically the same here).
