# SURFACES — crc10-gsm-pure (cycle_131)

> Surface enumeration for the T1 VULN_AUDIT. Every public entry point and
> every reachable code path is listed. This is the exhaustive inventory the
> T2 harness card will use to seed its fuzzer inputs.

## 1. Python public API

The package `crc10_gsm` is laid out as `src/crc10_gsm/` with one sub-module:

| File | Symbol | Kind | Visibility |
|---|---|---|---|
| `src/crc10_gsm/__init__.py` | `crc` | function | re-export (public) |
| `src/crc10_gsm/__init__.py` | `register` | function | re-export (public) |
| `src/crc10_gsm/__init__.py` | `__version__` | str constant | public |
| `src/crc10_gsm/__init__.py` | `__all__` | list | `["crc", "register"]` |
| `src/crc10_gsm/_crc10_gsm.py` | `crc` | function | private impl |
| `src/crc10_gsm/_crc10_gsm.py` | `register` | function | private impl |
| `src/crc10_gsm/_crc10_gsm.py` | `_MASK` | int (=0x3FF) | module-private |
| `src/crc10_gsm/_crc10_gsm.py` | `_POLY` | int (=0x175) | module-private |
| `src/crc10_gsm/_crc10_gsm.py` | `_XOROUT` | int (=0x3FF) | module-private |

### 1.1 `crc(data)` — single function entrypoint

```
Signature:  crc(data: bytes | bytearray | memoryview) -> int
Returns:    int in [0, 1024)  (masked to 10 bits)
Raises:     TypeError  if data is not bytes-like
Sidefx:     NONE (pure function; iterates `data` but does not mutate it)
```

**Code paths inside `crc`:**

1. **Type-guard branch** — `isinstance(data, (bytes, bytearray, memoryview))`:
   - True → continue to loop.
   - False → raise `TypeError(f"crc10_gsm.crc() expected bytes-like, got {type(data).__name__}")`.
2. **Outer loop** — `for byte in data` — iterates integer values 0..255.
3. **XOR-into-high-byte** — `crc_reg ^= (byte << 2) & _MASK` — masks to 10 bits.
4. **Inner bit loop (8 iters)** — fold through `_POLY=0x175` based on top bit.
5. **Finalisation** — `return (crc_reg ^ _XOROUT) & _MASK`.

**No other branches, no recursion, no exception handling inside the loop.**

### 1.2 `register()` — metadata accessor

```
Signature:  register() -> dict
Returns:    {"width": 10, "poly": 0x175, "init": 0x000, "refin": False,
             "refout": False, "xorout": 0x3FF, "check": 0x12A}
Raises:     NONE
Sidefx:     NONE (returns a fresh dict each call)
```

This is a constant accessor — no user-controllable input, no branches.

### 1.3 `__version__` — string constant

The string `"0.1.0"`. Read-only.

## 2. CLI surface (`crc10-gsm` → `crc10_gsm.__main__:main`)

The `[project.scripts]` entry in `pyproject.toml:14` registers:

```
crc10-gsm = "crc10_gsm.__main__:main"
```

So `python3 -m crc10_gsm` and the installed binary `crc10-gsm` are equivalent.

### 2.1 argparse flags

| Flag | nargs | Action | Default | Mutex |
|---|---|---|---|---|
| `--data` | `+` (1 or more) | store | `[]` | — |
| `--stdin` | 0 | store_true | `False` | mutex with `--data` (resolved at runtime) |
| `--self-test` | 0 | store_true | `False` | runs and exits before `--data`/`--stdin` |
| `--register` | 0 | store_true | `False` | runs and exits before `--data`/`--stdin` |

`main()` flow (lines 51–75 of `__main__.py`):

1. If `--self-test` → `_self_test()` → prints PASS/FAIL, returns 0/1.
2. If `--register` → prints `k=v` lines, returns 0.
3. If `--stdin` → reads `sys.stdin.buffer.read()` (raw bytes, **not** stripped).
4. Else → `_parse_data(args.data)` → `crc(data)` → prints `0x{hex}`.

### 2.2 CLI helper: `_parse_data(values)`

A list of strings from `--data` is converted to `bytes` via a three-tier fallback:

1. If **exactly one** value and its length is even: try `bytes.fromhex(value)`.
2. If that fails OR there are multiple values: iterate each value:
   - Strip `0x` prefix → `int(v, 16) & 0xFF`.
   - Else try `int(v, 16) & 0xFF`.
   - Else try `int(v) & 0xFF` (decimal).
   - Else fall back to `v.encode("latin-1")` — **the surprising one**.
3. Concatenate into `bytearray`.

This means `--data ZZZZ` does NOT error — it is silently treated as the
latin-1 bytes `ZZZZ` (0x5A 0x5A 0x5A 0x5A) and a CRC is computed over them.
This is intentional but is the single biggest behavioural surprise on the CLI.

### 2.3 CLI helper: `_self_test()`

```python
expected = 0x12A
actual = crc(b"123456789")
if actual != expected:
    print(f"FAIL: crc(b'123456789') = 0x{actual:03X}, expected 0x{expected:03X}", file=sys.stderr)
    return 1
print(f"PASS: crc(b'123456789') = 0x{actual:03X}")
return 0
```

No user input, no I/O. Trivial.

### 2.4 Return-code matrix

| Invocation | Exit code |
|---|---|
| `--self-test` PASS | 0 |
| `--self-test` FAIL | 1 |
| `--register` | 0 |
| `--data …` (any input) | 0 (even on latin-1 fallback) |
| `--stdin` (any input) | 0 |
| `--help` | 0 (argparse default) |
| No args | 0 (CRC of empty data = 0x3FF) |
| Invalid flag | 2 (argparse default) |

The CLI **never exits non-zero from a runtime error** — even malformed hex
like `--data ZZZZ` exits 0 with a valid-looking output. That is a
documentation/usability issue, not a vulnerability.

## 3. Module-internal surface

The leading underscore in `_crc10_gsm.py` is the Python convention for
"private". Nothing else imports it directly. It is reachable only via the
re-export chain in `__init__.py`.

## 4. Test surface (not a runtime attack surface, but covered for completeness)

`tests/test_crc10_gsm.py` (375 LOC, 35 test functions, 1090 parametrized
items) covers:

- 12 LOCKED ACs from `SPEC.md` §3.
- Type-error matrix: `None`, `int`, `str`, `list`, `dict`, `float` — 6 tests.
- Bytes-like variants: `bytes`, `bytearray`, `memoryview` — 4 tests.
- Byte-range 0..255 (single-byte CRC) — 256 tests.
- Length sweep `b"\x00" * n` for n=0..255 — 256 tests.
- Length sweep `b"\xff" * n` for n=0..127 — 128 tests.
- Determinism over 50 random 1024-byte inputs — 50 tests.
- Differential vs `_reference_crc` (independent pure-Python loop) — 50 tests.
- Deterministic oracle set — 30 entries × 2 (assert + dedup) = 60 tests.
- Edge: 1MiB random, all-zero 4096, all-ff 4096, single-bit walk, two-byte
  distinctness — 5 tests.
- CLI smoke: `--self-test`, `--data`, `--register`, `--stdin` — 4 tests.
- Fuzz extensions: random-64B × 64, random-lengths × 64, trailing-zero × 64,
  trailing-ff × 64 — 256 tests.

## 5. Out-of-scope surfaces (intentionally not exposed)

The following are deliberately **not** in this repo's surface:

- No `register` mutability (the dict is freshly built each call).
- No custom `init` argument (algorithm is fixed at init=0x000 per the spec).
- No streaming API (entire input is iterated via Python `for` loop).
- No multiprocessing, threading, or async.
- No file I/O, no network I/O.
- No subprocess invocation from the library.
- No C extension, no `ctypes`, no `cffi`.
- No `pickle`, no `eval`, no `exec`, no `compile`.
- No `os.system`, no `subprocess.run` from inside the library.

These absences are properties of the surface, not gaps — they mean the
attack surface is bounded by the two functions in §1 plus the four CLI
modes in §2.

## 6. Surfaces-count summary

| Surface | Count | Notes |
|---|---|---|
| Public functions | 2 | `crc`, `register` |
| Public constants | 1 | `__version__` |
| CLI flags | 4 | `--data`, `--stdin`, `--self-test`, `--register` |
| CLI helpers | 2 | `_parse_data`, `_self_test` |
| Private functions | 0 | (impl is inline in `crc`) |
| Private constants | 3 | `_MASK`, `_POLY`, `_XOROUT` |
| **Total reachable entry points** | **5** | 2 funcs + 4 CLI flags (register is also reachable via flag) |
