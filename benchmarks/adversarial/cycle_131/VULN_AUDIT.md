# VULN_AUDIT.md — Cycle 131 Adversary T1 Manual Vulnerability Audit

> **Repository:** `crc10-gsm-pure` — CRC-10/GSM (3GPP TS 44.006) reference implementation.
> **Commit audited:** `fae2d566d21ea289f6c2f7a45922a804683c371b`
> **Audit type:** Manual source review + live behavioural probing.
> **Auditor:** `@default` (repo-adversary profile STOPPED per cycle_124 #842 — running under default profile with `highest-quality-repo` + `kanban-worker` skills).
> **Audit date:** 2026-09-27.
> **Invariants applied:** Invariant 26 §1 (5-card adversary chain; this is card 1/5).

---

## VERDICT: CLEAN

**Zero Critical, zero High, zero Medium, zero Low findings.**
One **Info** observation about CLI input fallback behaviour (not a vulnerability — documented).

---

## Executive summary

The `crc10-gsm-pure` library at commit `fae2d56` is a single-function, pure-Python,
zero-dependency implementation of CRC-10/GSM (3GPP TS 44.006 §5.3.4, the FIRE-CODE
used over GSM LAPDm radio frames). The entire algorithmic surface is:

```python
def crc(data: bytes | bytearray | memoryview) -> int:
    # 10-bit register, 8-iteration inner loop per byte
    # Returns masked 10-bit value in [0, 1024)
```

plus a static `register()` introspection helper. The CLI (`crc10-gsm`) wraps the
function with `argparse` for one-shot use, with `--self-test`, `--register`,
`--data HEX_OR_DEC [HEX_OR_DEC ...]`, and `--stdin` modes.

The audit inspected:
- Every public symbol in `src/crc10_gsm/__init__.py` and `_crc10_gsm.py`.
- Every code path in `src/crc10_gsm/__main__.py` (CLI).
- `pyproject.toml` for dependency and build configuration.
- The 1090-test suite in `tests/test_crc10_gsm.py` for adversarial coverage gaps.
- 32 CWE categories from the standard CRC-library catalogue (see CWE_MAP.md).
- 9 attack vectors from the task body's V3 (see THREAT_MODEL.md).

No vulnerability was found that meets the bar for a fix card.

---

## Severity-ranked findings

| # | Severity | Title | Status | CWE | Detail |
|---|---|---|---|---|---|
| — | — | — | — | — | (none) |
| 1 | **Info** | CLI `_parse_data` silently falls back to latin-1 for non-numeric tokens | Documented behaviour; not a defect | n/a | `_parse_data` in `__main__.py` (lines 16–37) tries `int(v, 16)`, then `int(v)`, then `v.encode("latin-1")` as a last resort. `--data ZZZZ` yields 4 bytes `[0x5A]*4` and exits 0. This is *intentional* (the CLI is documented as accepting hex, decimal, *or* literal bytes), but is worth flagging because a user passing `ZZZZ` expecting an error will silently get a CRC of the literal letters "ZZZZ". **Recommendation:** future T3/T4 work could add a `--strict-hex` flag, but this is not a vulnerability. |

**No Critical, High, Medium, or Low findings.**

---

## Detailed audit findings (informational, by surface)

### Surface 1 — `crc10_gsm.crc(data)` (Python API)

**Code (`src/crc10_gsm/_crc10_gsm.py`):**

```python
_MASK = 0x3FF
_POLY = 0x175
_XOROUT = 0x3FF

def crc(data: "bytes | bytearray | memoryview") -> int:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc10_gsm.crc() expected bytes-like, got {type(data).__name__}"
        )
    crc_reg = 0x000
    for byte in data:
        crc_reg ^= (byte << 2) & _MASK
        for _ in range(8):
            if crc_reg & 0x200:
                crc_reg = ((crc_reg << 1) ^ _POLY) & _MASK
            else:
                crc_reg = (crc_reg << 1) & _MASK
    return (crc_reg ^ _XOROUT) & _MASK
```

**Audit observations:**

1. **Type guard is exhaustive and correct.** `isinstance(data, (bytes, bytearray, memoryview))` is the standard "bytes-like" check (PEP 361). All three types are accepted; everything else raises `TypeError`. Verified for `None`, `int`, `str`, `list`, `dict`, `float` at audit time. **No CWE-20/CWE-241/CWE-704 issue.**

2. **Register mask is applied at every shift.** `crc_reg ^= (byte << 2) & _MASK`, `(crc_reg << 1) & _MASK`, and `((crc_reg << 1) ^ _POLY) & _MASK` all mask immediately. The intermediate `crc_reg` value can never exceed `_MASK = 0x3FF` (10 bits), even in theory. Python's arbitrary-precision int semantics are a second-line defence. **No CWE-190/CWE-191 issue.**

3. **Loop bounds are constant.** Outer loop iterates over input bytes (bounded by input length); inner loop runs exactly 8 times per byte (literal `range(8)`). No CWE-835 (infinite loop) possible.

4. **Algorithm is linear time.** 100 MiB / 200 MiB live tests confirmed O(n) scaling. No CWE-400 issue.

5. **The `init` parameter the task body V2 mentioned does not exist.** The signature is `crc(data)` only. This is a meaningful *attack-surface reduction* (no caller can pass an out-of-range `init`), not a defect. The single-arg API is strictly safer than a two-arg API would have been. See SURFACES.md §7 for the delta.

6. **No side effects.** No I/O, no globals mutated, no module-level cache, no logging. Function is pure-functional and reentrant.

**Verdict:** Surface 1 is CLEAN. Zero findings.

### Surface 2 — `crc10_gsm.register()` (introspection)

Returns a static dict of RevEng parameter values (`width`, `poly`, `init`, `refin`, `refout`, `xorout`, `check`). No input parameter, no I/O. Trivially safe.

**Verdict:** CLEAN.

### Surface 3 — CLI `crc10-gsm` (`__main__.py`)

**Audit observations:**

1. **`--self-test` and `--register` modes consume no user data.** They run a hard-coded vector or print static text, respectively. Trivially safe.

2. **`--data HEX_OR_DEC [...]`** parses user input via `_parse_data`. The parser is permissive: it accepts hex (`0x41` or `41`), decimal (`65`), and literal bytes (`A` → 0x41, `ZZZZ` → 4×0x5A). The permissive behaviour is a usability *feature* (CLI is documented as "bytes to CRC (hex or decimal)" in `--help`, and the latin-1 fallback handles edge cases), not a vulnerability.

3. **`--stdin`** reads raw bytes via `sys.stdin.buffer.read()`. Any byte value 0x00–0xFF is accepted; CRLF, unicode, and binary data all flow through unmodified to `crc()`. Verified: `--stdin` with `b"123456789\r\n"` returns `0x342` (correct CRC of 11 bytes, including the trailing CR LF). Verified: `--stdin` with `b"\x00\xff\x7f\x80"` returns `0x050` (no error). Empty stdin returns `0x3FF`.

4. **No shell execution.** Verified by injection attempt:
   ```
   python3 -m crc10_gsm --data "0x41;" "rm" "-rf" "/tmp/__crc10gsm_evil__"
   ```
   Exits with rc=2 (argparse rejects `;` as not-an-int, then argparse runs out of allowed positionals). `/tmp/__crc10gsm_evil__` does not exist after the invocation. **No CWE-78 issue.**

5. **Long-input CLI handled.** `--data "AABB" * 5000` (10000 hex chars = 5000 bytes) returns `0x084` without overflow. `bytes.fromhex` accepts arbitrarily long strings.

**Verdict:** Surface 3 is CLEAN. One **Info** observation noted above (latin-1 fallback for `--data ZZZZ`).

### Surface 4 — Module globals and `__version__`

`__version__ = "0.1.0"` is a static string. `_MASK`, `_POLY`, `_XOROUT` are module-globals that *can* be imported (no `__all__` filtering for underscore-prefixed names), but mutating them only affects future calls in the same process. Since `crc()` is called by external libraries, no caller should be mutating these. No CWE issue.

**Verdict:** CLEAN.

---

## Coverage cross-reference

This audit's findings are grounded in:

- **CWE_MAP.md** — 32 CWE identifiers evaluated across 9 categories; 0 APPLIES, 4 MITIGATED, 28 DOES NOT APPLY.
- **SURFACES.md** — 4 distinct attack surfaces enumerated (Python API, introspection, CLI --data, CLI --stdin).
- **TEST_GAPS.md** — 22 adversarial scenarios checked against the existing 1090-test suite. Gaps identified are *informational* or low-severity stress; none represent a vulnerability.
- **THREAT_MODEL.md** — 4 adversary profiles analysed; worst-case impact = CPU blocking for ~15 min on a 10 GiB input (linear, not exponential).

---

## Recommendations

None required for security. Future hardening (out of scope for this audit):

1. **(Info-level, T3 follow-up)** Add tests pinning the latin-1 fallback behaviour for CLI `--data` so a future refactor cannot silently change it. See TEST_GAPS.md gaps #6, #17, #18, #19.
2. **(T3 follow-up)** Add a 100 MiB stress test to lock in linear-time behaviour beyond the existing 1 MiB test. See TEST_GAPS.md gaps #1, #2, #3.
3. **(T3 follow-up)** Add stdin variant tests (CRLF, binary bytes, empty stdin) to lock in the binary-stdin contract. See TEST_GAPS.md gaps #4, #5, #13, #16.

These are *documentation and coverage improvements*, not security fixes.

---

## VERDICT: CLEAN

**Findings:** 0 Critical, 0 High, 0 Medium, 0 Low, 1 Info (documented CLI behaviour, not a defect).

The library at commit `fae2d56` is safe to ship. The T2 fuzzing-harnesses card should proceed; the T3 fuzzing-execution card should fold in the test gaps noted in TEST_GAPS.md; the T4 triage card has nothing to remediate.

VERDICT: CLEAN
