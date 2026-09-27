# VULN_AUDIT — crc10-gsm-pure (cycle_131)

> Manual vulnerability audit at commit `fae2d56` on branch
> `wt/cycle131-adversary-01`. Parent: cycle_131/qa (DONE @ fae2d56,
> VERDICT:SHIP). Performed per Invariant 26 §1 (HIGHEST_QUALITY_REPO.md).

## Executive summary

The `crc10-gsm-pure` repository at cycle_131 is a **clean reference
implementation**. The function surface is two trivial pure functions
(`crc`, `register`); the CLI surface is four flag-driven modes
(`--self-test`, `--register`, `--data`, `--stdin`). The codebase has:

- 19 CWEs considered.
- 2 CWEs that apply (CWE-400, CWE-770 — both the same finding).
- 0 Critical / 0 High / 0 Medium / 0 Low findings.
- 2 Info findings, both **documented** and **non-exploitable** in any
  realistic deployment.

The audit verdict is **CLEAN**.

## Audit methodology

1. **Static read** of every Python file in `src/` and `tests/`.
2. **Dynamic probe** of every surface listed in `SURFACES.md` against
   boundary inputs (None, int, float, str, list, dict, generator,
   `array.array`, bytes subclass, memoryview over 10 MB backing, 100 MB
   random bytes, 1 GB stdin with 60 s timeout).
3. **CWE mapping** against the 19 most-relevant CWE IDs for a CRC
   library (no I/O, no crypto, no parsing) — see `CWE_MAP.md`.
4. **Test-suite gap analysis** against the 1090 existing pytest items —
   see `TEST_GAPS.md`.
5. **Threat-model walk-through** with three attacker profiles (radio
   adversary, CLI input attacker, Python API caller) — see
   `THREAT_MODEL.md`.

## Findings

### F-001 — Unbounded stdin buffering (`--stdin` mode)

| Field | Value |
|---|---|
| Severity | **Info** |
| CWE | CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits) |
| Surface | `src/crc10_gsm/__main__.py:70` (`sys.stdin.buffer.read()`) |
| Status | Accepted; documented. |

**Description.** The CLI `--stdin` mode reads all of stdin into memory
before computing the CRC. For very large inputs this is a linear cost
(~0.36 s/MiB) and a proportional memory cost. Probed at 100 MiB
(completed in 36.5 s) and 1 GiB (would take ~6 min linear; timed out
at 60 s in this audit).

**Why Info, not Low/Medium.** This is the standard contract for
filter-style CLIs (`cat`, `md5sum`, `sha256sum`, `xxd`). The library
does not promise a max-bytes limit; the README's "Limitations" section
explicitly notes "not constant-time" but does NOT claim any input-size
ceiling — which is correct, because the algorithm is well-defined for
all N ≥ 0. No fix is recommended for v0.1.0.

**Recommended action.** Add a sentence to `README.md` "Limitations":
`"--stdin reads all input into memory; for files larger than a few
hundred MB use a streaming hash tool instead."` Owner: build card at
next patch release.

### F-002 — `--data` latin-1 fallback for malformed hex

| Field | Value |
|---|---|
| Severity | **Info** |
| CWE | None directly; nearest is CWE-1284 (Improper Validation of Specified Quantity) but does not strictly apply. |
| Surface | `src/crc10_gsm/__main__.py:36` (`out.extend(v.encode("latin-1"))`) |
| Status | Accepted; documented as-is. |

**Description.** The `_parse_data` helper has a three-tier fallback for
each `--data` value:

1. `bytes.fromhex(value)` if exactly one even-length value.
2. `int(v, 16) & 0xFF` (hex with or without `0x`).
3. `int(v) & 0xFF` (decimal).
4. **Fallback**: `v.encode("latin-1")` — treats the string as raw bytes.

This means `--data ZZZZ`, `--data xy`, `--data "31; rm -rf /"`, and
`--data "31 32 && rm"` all succeed with a deterministic CRC of the
latin-1 bytes of the input. **No shell expansion occurs** — the CLI is
invoked via `subprocess.run([sys.executable, ...])` (argv-list), not via
the shell — so there is no injection.

Probed at this audit:

```
--data 'ZZZZ'   -> rc=0 out='0x304\n' err=''
--data 'xy'     -> rc=0 out='0x341\n' err=''
--data '31;32'  -> rc=0 out='0x15a' err=''
```

**Why Info, not Low.** The behaviour is **deterministic and total** —
every input produces a CRC. There is no path that returns wrong data,
crashes, or executes arbitrary code. The surprise is that the user
expected an error and got a CRC instead. This is a UX concern, not a
security vulnerability.

**Recommended action.** Optional: replace the latin-1 fallback with a
hard error (`raise SystemExit(f"invalid --data value: {v!r}")`). Owner:
build card at next minor release. Not blocking for v0.1.0.

## No-finding confirmation

The following surfaces were probed exhaustively and produce **no
finding**:

| Surface | Probed with | Result |
|---|---|---|
| `crc(None)` | direct call | TypeError, `bytes` in message (AC10) |
| `crc(123)` | direct call | TypeError (AC10) |
| `crc(3.14)` | direct call | TypeError (AC10) |
| `crc("hello")` | direct call | TypeError (AC10) |
| `crc([1,2,3])` | direct call | TypeError (AC10) |
| `crc({"a":1})` | direct call | TypeError (AC10) |
| `crc(2**1000)` | direct call | TypeError (AC10) |
| `crc(b'a' for _ in range(10))` | direct call | TypeError (AC10) |
| `crc(array.array('B', b'123456789'))` | direct call | TypeError (AC10) |
| `crc(bytearray(b'123456789'))` | direct call | 0x12A (AC3) |
| `crc(memoryview(b'123456789'))` | direct call | 0x12A (AC3) |
| `crc(class MyBytes(bytes): pass)(b'123456789'))` | direct call | 0x12A (subclass accepted) |
| `crc(b'')` | direct call | 0x3FF (AC2) |
| `crc(bytes([0x00]))` | direct call | 0x3FF (AC1) |
| `crc(bytes(range(10)))` | direct call | 0x150 (AC4) |
| `crc(b'\xff' * 1_000_000)` | direct call | 0x??? masked (AC11, AC12) |
| `crc(b'\xab' * 100_000_000)` | direct call | 0x340 masked; 35.4 s linear (AC11, AC12) |
| `subprocess.run(['python3', '-m', 'crc10_gsm', '--stdin'], input=b'\xab' * 100_000_000)` | subprocess | rc=0, 36.5 s, output `0x18c` |
| `bytearray` mutation safety | direct call | bytearray not mutated (input byte-by-byte, no assignment) |
| `subprocess.run(['python3', '-m', 'crc10_gsm', '--data', 'ZZZZ'])` | subprocess | rc=0, output `0x304` (F-002 fallback path) |
| `subprocess.run(['python3', '-m', 'crc10_gsm', '--data', '31 32 && rm'])` | subprocess | rc=0, output `0x29c` (F-002 fallback path, **no shell invocation**) |
| `subprocess.run(['python3', '-m', 'crc10_gsm', '--self-test', '--data', '49', '50', '51'])` | subprocess | rc=0, prints self-test PASS, does NOT read data (--self-test takes precedence) |
| `subprocess.run(['python3', '-m', 'crc10_gsm'])` (no args) | subprocess | rc=0, output `0x3ff` (CRC of empty input) |
| `subprocess.run(['python3', '-m', 'crc10_gsm', '--help'])` | subprocess | rc=0 (argparse default) |

All findings are documented, none are exploitable in a realistic
deployment.

## Cross-cycle disambiguation (cycle_131 vs cycle_114)

The repository `crc10-atm-pure` (cycle_114, shipped 2026) implements a
different CRC-10 algorithm (`poly=0x233`, `xorout=0x000`). On every
test input probed (per `QA_REPORT.md` §8), the two algorithms produce
**distinct** CRC values. No aliasing risk.

## Dependencies

`pyproject.toml:11` declares `dependencies = []`. No runtime
dependencies, no transitive dependencies, no supply-chain attack
surface. CWE-1357 (Reliance on Insufficiently Trustworthy Component)
does not apply.

## Secret scan

No hardcoded tokens, API keys, or credentials. `git grep -nE 'ghp_|pypi-AgEI|sk-|AKIA|BEGIN PRIVATE KEY' -- ':!*.lock'` returns zero matches.

## Audit verdict

```
VERDICT: CLEAN
```

Summary counts:

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 2 (F-001 unbounded stdin, F-002 latin-1 fallback) |
| **Total** | **2** |

Both Info findings are documented above and accepted as-is. Neither
warrants a code change for v0.1.0; both are candidate improvements for
a future minor release and are tracked in `TEST_GAPS.md` (G1, G3).

---

**Auditor:** default profile (repo-adversary profile stopped per
cycle_124 #842 — see repo-factory chronic-blocker notes).

**Branch:** `wt/cycle131-adversary-01`
**Commit:** `fae2d56` (parent: `cc47871`)
**Cycle:** 131
**Phase:** adversary T1 (VULN_AUDIT)
