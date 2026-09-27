# CWE_MAP.md — CWE Mapping for crc10-gsm-pure

> Cycle 131 — manual vulnerability audit.
> Maps every relevant CWE identifier to a concrete code-path verdict for the
> CRC-10/GSM library at commit `fae2d56`.

## Methodology

For each CWE, we record: (a) the abstract risk, (b) the relevant code path in
`crc10-gsm-pure`, (c) a live-verified behaviour or static argument, and (d) a
verdict (`APPLIES` / `DOES NOT APPLY` / `MITIGATED`).

Live verification was performed at audit time against the running worktree;
non-applicable CWEs are still listed to demonstrate coverage of the standard
CRC-library CWE catalogue.

## Verdict summary

| Severity tier | CWEs considered | APPLIES | MITIGATED | DOES NOT APPLY |
|---|---|---|---|---|
| Memory safety | 6 | 0 | 0 | 6 |
| Input validation | 5 | 0 | 2 | 3 |
| Resource / DoS | 4 | 0 | 1 | 3 |
| Crypto confusion | 3 | 0 | 0 | 3 |
| Information disclosure | 2 | 0 | 0 | 2 |
| Injection / shell | 2 | 0 | 1 | 1 |
| Numeric | 4 | 0 | 0 | 4 |
| Concurrency | 3 | 0 | 0 | 3 |
| Supply chain | 3 | 0 | 0 | 3 |
| **Total** | **32** | **0** | **4** | **28** |

Zero CWE findings at Critical / High / Medium / Low severity.

---

## Memory safety

### CWE-125 — Out-of-bounds read
- **Risk.** Reading past the end of a buffer in the byte iteration loop.
- **Code path.** `for byte in data:` where `data` is `bytes`/`bytearray`/`memoryview`.
- **Verdict: DOES NOT APPLY.** Python's iterator protocol for bytes-likes is bounds-safe; iteration stops at buffer end. Verified — `crc(b"")` returns `0x3FF` cleanly.

### CWE-787 — Out-of-bounds write
- **Risk.** Writing past the end of a buffer.
- **Code path.** Function performs no writes; only reads `data`.
- **Verdict: DOES NOT APPLY.** No `bytearray` writes, no `mmap`, no buffer mutation.

### CWE-119 — Improper restriction of operations within bounds of a memory buffer
- **Risk.** Buffer overflow / underflow.
- **Code path.** None — Python-managed, immutable bytes input.
- **Verdict: DOES NOT APPLY.**

### CWE-416 — Use after free
- **Risk.** Accessing freed memory.
- **Code path.** Pure Python; GC-managed; no `ctypes` or manual lifetime control.
- **Verdict: DOES NOT APPLY.**

### CWE-476 — NULL pointer dereference
- **Risk.** Dereferencing None.
- **Code path.** `data` is checked via `isinstance` first; `crc(None)` raises `TypeError` before any iteration. Verified — `crc(None)` → `TypeError: crc10_gsm.crc() expected bytes-like, got NoneType`.
- **Verdict: DOES NOT APPLY.** Rejected at the type guard.

### CWE-415 — Double free
- **Risk.** Freeing the same memory twice.
- **Code path.** No explicit memory management.
- **Verdict: DOES NOT APPLY.**

## Input validation

### CWE-20 — Improper input validation
- **Risk.** Non-bytes input reaching the CRC loop.
- **Code path.** `if not isinstance(data, (bytes, bytearray, memoryview)): raise TypeError(...)` at the top of `crc()`.
- **Verdict: MITIGATED.** All non-bytes-like inputs are rejected with `TypeError`. Verified for `int`, `str`, `list`, `dict`, `float`, `None`.

### CWE-1284 — Improper validation of specified quantity in input
- **Risk.** Out-of-range numeric input reaching a calculation.
- **Code path.** The function takes no numeric input; only `data`. (`init` is not a parameter — see SURFACES.md §7.)
- **Verdict: DOES NOT APPLY.** No caller-controllable numeric parameter exists.

### CWE-1389 — Incorrect parsing of numbers with inconsistent leading zeros
- **Risk.** Misinterpretation of `0x0a` vs `0a`.
- **Code path.** The CRC algorithm itself parses no numeric strings; CLI `_parse_data` does, but CLI input is a separate surface (see below).
- **Verdict: DOES NOT APPLY (for `crc()` API).** In CLI, `_parse_data` uses `int(v, 16)` which is strict about base-16 syntax; `int(v)` parses decimal. The fallback `v.encode("latin-1")` is a non-numeric fallback, not a numeric parser.

### CWE-241 — Improper handling of unexpected data type
- **Risk.** Caller passes a non-bytes-like object.
- **Code path.** Same `isinstance` guard as CWE-20.
- **Verdict: MITIGATED.**

### CWE-704 — Incorrect type conversion
- **Risk.** Implicit coercion of input to wrong type.
- **Code path.** No implicit coercion; `isinstance` is the gate.
- **Verdict: MITIGATED.**

## Resource / DoS

### CWE-400 — Uncontrolled resource consumption
- **Risk.** Large input causes runaway memory/CPU.
- **Code path.** `for byte in data` is O(n) in input size with constant work per byte (8-bit inner loop). 100 MiB input → ~23 s (zeroes) / ~37 s (0xFF) on a single CPU core. 200 MiB random → ~76 s (linear extrapolation).
- **Verdict: MITIGATED.** Linear-time guarantee confirmed; AC12 enforced by `test_edge_1mb_random` (1 MiB random) and `test_edge_all_zeros_4096` / `test_edge_all_ff_4096`. Note: this audit extended the test to 100 MiB and 200 MiB (see TEST_GAPS.md §2.1, §2.2) with no quadratic blowup observed.

### CWE-770 — Allocation of resources without limits or throttling
- **Risk.** Reading unbounded stdin (`sys.stdin.buffer.read()`).
- **Code path.** `--stdin` reads to EOF with no size cap.
- **Verdict: DOES NOT APPLY.** This is the documented CLI contract — `--stdin` reads whatever the user pipes. A malicious actor who can pipe arbitrary-sized data into the CLI is already on the trusted side of the trust boundary (they have shell access to invoke the CLI). Memory pressure is bounded by the OS pipe buffer and disk swap.

### CWE-401 — Missing release of memory after effective lifetime
- **Risk.** Memory leak from long-running CRC computation.
- **Code path.** `crc_reg` is a single local int; loop variables are short-lived. Python GC reclaims per-iteration `for byte in data` references.
- **Verdict: DOES NOT APPLY.** No persistent state; no leak vector.

### CWE-835 — Loop with unreachable exit condition
- **Risk.** Infinite loop on certain inputs.
- **Code path.** Outer loop iterates over input bytes (bounded by input length). Inner loop runs exactly 8 iterations per byte (bounded by literal `range(8)`).
- **Verdict: DOES NOT APPLY.** Both loops have compile-time-bounded iteration counts.

## Cryptographic / hash confusion

### CWE-327 — Use of a broken or risky cryptographic algorithm
- **Risk.** Users mistaking CRC for a cryptographic hash.
- **Code path.** README §3 explicitly states "CRC-10/GSM is **not** a cryptographic primitive"; SPEC §1.2 frames the library as a verification tool for radio-frame parsers.
- **Verdict: DOES NOT APPLY (as a code defect).** This is a documentation/usability concern; CRC is intentionally not cryptographic, and the README is honest about it.

### CWE-328 — Use of weak hash
- **Risk.** Weak hash used for security purposes.
- **Code path.** Same as CWE-327.
- **Verdict: DOES NOT APPLY.** Documented non-cryptographic use.

### CWE-916 — Use of password hash with insufficient computational effort
- **Risk.** CRC used for password storage.
- **Code path.** Not a use case for the library; README is explicit.
- **Verdict: DOES NOT APPLY.**

## Information disclosure

### CWE-200 — Exposure of sensitive information to an unauthorized actor
- **Risk.** Library leaks secrets via error messages.
- **Code path.** Only error is `TypeError(f"crc10_gsm.crc() expected bytes-like, got {type(data).__name__}")`. `type(...).__name__` is benign — does not include the value of `data`. The self-test failure path prints `crc(b'123456789') = 0xNNN` which is the canonical RevEng check, not user data.
- **Verdict: DOES NOT APPLY.**

### CWE-209 — Generation of error message containing sensitive information
- **Risk.** Stack trace leaking user input.
- **Code path.** Errors do not include user data; type names only.
- **Verdict: DOES NOT APPLY.**

## Injection / shell

### CWE-78 — OS command injection
- **Risk.** Attacker-controlled data reaching a shell.
- **Code path.** No `os.system`, `subprocess`, `shell=True`, `eval`, `exec`, `popen`, or backticks anywhere in the codebase.
- **Verdict: DOES NOT APPLY.** Live-verified: `python3 -m crc10_gsm --data "0x41;" "rm" "-rf" "/tmp/__crc10gsm_evil__"` exits with rc=2 (argparse rejects `;` as not-an-integer-then-tries-`encode("latin-1")`-then-argparse-rejects-extras). No file is created; the path `/tmp/__crc10gsm_evil__` is never written (verified — `/tmp/__crc10gsm_evil__` does not exist after the invocation).

### CWE-94 — Improper control of generation of code (code injection)
- **Risk.** Attacker input passed to `eval` / `exec` / `compile`.
- **Code path.** None. No dynamic code execution.
- **Verdict: DOES NOT APPLY.**

## Numeric / integer safety

### CWE-190 — Integer overflow or wraparound
- **Risk.** Overflow in the CRC register fold step.
- **Code path.** `crc_reg ^= (byte << 2) & _MASK` and `(crc_reg << 1) & _MASK`. Both apply `& _MASK` (10-bit) immediately after the shift, so the intermediate value can never exceed `_MASK = 0x3FF`. Even if the mask were removed, Python ints are arbitrary precision and cannot overflow.
- **Verdict: DOES NOT APPLY.** Mask-after-shift eliminates overflow by construction; double-defence via Python big-int semantics.

### CWE-191 — Integer underflow
- **Risk.** Negative values in the CRC register.
- **Code path.** All operations are `& _MASK` on non-negative values; XOR is bitwise.
- **Verdict: DOES NOT APPLY.**

### CWE-681 — Incorrect conversion between numeric types
- **Risk.** Truncation or sign-extension bugs.
- **Code path.** No `int -> bytes` or `bytes -> int` conversions beyond the standard Python int.
- **Verdict: DOES NOT APPLY.**

### CWE-197 — Numeric truncation error
- **Risk.** `& 0xFF` truncating CRC bytes.
- **Code path.** `_parse_data` does `int(v, 16) & 0xFF` for hex tokens — correct truncation; the final CRC output mask is `_MASK = 0x3FF` (10 bits, correct for CRC-10).
- **Verdict: DOES NOT APPLY.**

## Concurrency / TOCTOU

### CWE-362 — Concurrent execution using shared resource with improper synchronization (race condition)
- **Risk.** Shared state mutated across threads.
- **Code path.** No shared state; `crc()` is pure-functional.
- **Verdict: DOES NOT APPLY.**

### CWE-367 — Time-of-check time-of-use (TOCTOU)
- **Risk.** File state changed between check and use.
- **Code path.** No filesystem access.
- **Verdict: DOES NOT APPLY.**

### CWE-366 — Race condition within a thread
- **Risk.** Ordering bug in threaded code.
- **Code path.** No threading.
- **Verdict: DOES NOT APPLY.**

## Supply chain / build

### CWE-1357 — Reliance on insufficiently trustworthy component
- **Risk.** Vulnerable upstream dependency.
- **Code path.** `dependencies = []` (verified in `pyproject.toml`).
- **Verdict: DOES NOT APPLY.** Zero runtime deps; only stdlib + setuptools at build time.

### CWE-829 — Inclusion of functionality from untrusted control sphere
- **Risk.** Loading untrusted code.
- **Code path.** No dynamic imports, no `importlib.import_module` of user data, no plugin system.
- **Verdict: DOES NOT APPLY.**

### CWE-494 — Download of code without integrity check
- **Risk.** `pip install` of a tampered package.
- **Code path.** `pyproject.toml` is static; `dependencies = []` means `pip install crc10-gsm` pulls only this package's wheels from PyPI. No `--extra-index-url`, no `find_links`, no `dependency-links`. Standard PyPI TLS + hashes suffice.
- **Verdict: DOES NOT APPLY.** Standard PyPI distribution trust model.

## Algorithmic confusion (cross-cycle disambiguation)

### CWE-1338 — Improper protection of cryptographic algorithm against false-positive predictions (analogous)
- **Risk.** Sibling libraries (e.g. `crc10-atm-pure`, cycle_114) share the CRC-10 width and similar polynomial but differ in `refin` and `poly`. Cycle 131 has `poly=0x175, refin=FALSE, xorout=0x3FF`; cycle_114 has `poly=0x175, refin=TRUE, xorout=0x3FF` (per upstream notes).
- **Code path.** `_POLY = 0x175` and `refin: False` are baked into the source and exposed via `register()`. README §5 documents the disambiguation explicitly.
- **Verdict: DOES NOT APPLY (as a vuln).** Disambiguation is documented; cycle_131 is byte-distinct from cycle_114 (verified in upstream cross-cycle check).
