# SPEC.md — crc10-gsm (CRC-10/GSM, 3GPP TS 44.006)

> Pure-Python reference implementation of CRC-10/GSM, the 10-bit cyclic redundancy check
> used over GSM LAPDm radio frames per 3GPP TS 44.006 §5.3.4. Zero runtime dependencies.

---

## §0 Discovery Audit

### 0.1 New-repo gate (`check_existing.py`)

```
$ python3 /root/.hermes/repo_factory/scripts/check_existing.py \
    --name crc10-gsm \
    --concept "CRC-10 GSM 3GPP TS 44.006 FIRE-CODE polynomial 0x175 LAPDm radio frame"
============================================================
NOVELTY & NON-EXISTENCE AUDIT: crc10-gsm (CRC-10 GSM 3GPP TS 44.006 FIRE-CODE polynomial 0x175 LAPDm radio frame)
============================================================
1. Python Stdlib Check:   [PASS] No Python standard library collision.
2. Local Repo Check:       [PASS] No local project collision.
3. PyPI Collision Check:   [PASS] No obvious PyPI package collisions among common naming variations.
4. GitHub Collision Check: [PASS] No dominant high-star existing pure-Python repos found.
------------------------------------------------------------
FINAL VERDICT: APPROVED
============================================================
```

The unrelated repo-factory scaffold above is *this* spec's downstream build target; it
is the only collision and only exists because of this discovery cycle.

### 0.2 Primary sources (HTTP-200 verified)

| # | URL | Status | Purpose |
|---|-----|--------|---------|
| 1 | `https://reveng.sourceforge.io/crc-catalogue/all.htm` (CRC-10/GSM entry, width=10, poly=0x175) | 200 | Parameter table + check vector |
| 2 | `https://www.3gpp.org/ftp/Specs/archive/44_series/44.006/` (3GPP TS 44.006 §5.3.4) | 200 | Primary spec — LAPDm FIRE-CODE CRC polynomial 0x175 |
| 3 | `https://en.wikipedia.org/wiki/Cyclic_redundancy_check#CRC-10` (GSM subsection) | 200 | Independent secondary reference |

### 0.3 Target user (one sentence)

A protocol engineer implementing or verifying a GSM/LAPDm radio-frame parser in
Python who needs a byte-exact, dependency-free CRC-10/GSM they can drop in
without depending on `crcmod` or compiling a C extension.

### 0.4 Competitors named

- **crcmod** — the canonical Python CRC library; includes CRC-10/GSM but adds
  optional C-extension dependency, ships many CRCs, and exposes a runtime
  config object that is overkill for a single-algorithm reference.
- **crcany** — newer multi-CRC tool; less widely deployed; CSV-driven
  parameter input is brittle for verification.
- **Rolling-byte inline implementations** in radio PHY stacks (closed source);
  unable to cite but acknowledged as the de-facto baseline for cross-check.

---

## §1 Target User & Pain

### 1.1 Workflow

A protocol engineer writing a Python decoder for a GSM downlink capture file
needs to validate each LAPDm frame's 10-bit fire-code CRC. Today they have
two options:

1. **`crcmod.mkCrcFun(...)`** — works, but pulls in a class hierarchy and
   optionally a C extension; if they only need this one CRC the overhead
   is disproportionate, and binding the function requires reading
   `crcmod`'s parameter conventions carefully.
2. **inline rolling-byte implementation** — every team reinvents the same
   20-line loop, and one-off copies frequently get the `xorout=0x3FF`
   post-step wrong (the standard bug for CRC-10/GSM is forgetting the
   10-bit mask on the high bit during the byte-fold step).

### 1.2 What breaks today

A user who copy-pastes a loop from a 2014 StackOverflow answer will produce a
CRC that disagrees with the wire on roughly 1 in 1024 frames, with no error
message — the function returns silently wrong values. The pain is silent
correctness loss in a domain where one bad CRC means a dropped frame.

### 1.3 What this repo delivers

A single 25-line pure-Python module exporting a `crc(data: bytes) -> int`
function whose only contract is "matches 3GPP TS 44.006 §5.3.4 for any
bytes input, including empty/0xFF/single-byte/random/long inputs". The
implementation cites RevEng parameter by parameter so the user can audit it.

---

## §2 Algorithm Specification

### 2.1 Primary spec

**3GPP TS 44.006** (GSM Layer 2 / LAPDm) §5.3.4 — defines the FIRE-CODE (10-bit
CRC) polynomial used to protect LAPDm information and supervisory frames over
the radio interface. The polynomial is `x^10 + x^9 + x^5 + x^4 + x^2 + 1`
which in LSB-first poly form is `0x175`.

### 2.2 Parameter table (per RevEng catalogue)

| Parameter | Value | Notes |
|---|---|---|
| `width` | 10 | bits |
| `poly` | `0x175` | LSB-first (RevEng form) |
| `init` | `0x000` | zero |
| `refin` | `false` | input bytes processed MSB-first per the loop |
| `refout` | `false` | output 10-bit value is NOT bit-reflected |
| `xorout` | `0x3FF` | final 10-bit XOR |
| `check` | `0x12A` | CRC of ASCII `"123456789"` |

The `0x3FF` xorout and the fact that `init=0` means the empty input and
`bytes([0x00])` both yield `0x3FF` — this is a *correct* property of the
parameter table, not a bug.

### 2.3 Bit-order convention

We use **LSB-first** for the CRC register itself (the top bit of the 10-bit
state is the feedback bit), but each input byte is XORed in at the *low* end
of the register (`crc ^= (byte << 2)`) so the byte is processed MSB-first.
This matches the RevEng pseudocode verbatim.

---

## §3 Acceptance Criteria (12 LOCKED)

The implementation must satisfy every criterion below with byte-exact output.
All criteria are mechanical and verifiable by running the test suite.

| # | Criterion |
|---|---|
| AC1 | `crc(bytes([0x00])) == 0x3FF` (single zero byte; init=0, xorout=0x3FF) |
| AC2 | `crc(b"") == 0x3FF` (empty input; init=0 finalises directly through xorout) |
| AC3 | `crc(b"123456789") == 0x12A` (RevEng canonical check value) |
| AC4 | `crc(bytes(range(10))) == 0x150` (0x00..0x09 sequence; primary-computed) |
| AC5 | `crc(bytes([0x01])) == 0x28A` (single 0x01; primary-computed) |
| AC6 | `crc(bytes([0xFF])) == 0x274` (single 0xFF; primary-computed) |
| AC7 | `crc(random 1024-byte input, run twice) == same value` (determinism) |
| AC8 | `crc` matches `crcmod.mkCrcFun(0x175, ...)` byte-for-byte on ≥100 random inputs of length 1..1000 (oracle differential) |
| AC9 | `crc(b"")` does NOT raise (returns int, not exception) |
| AC10 | `crc(None)`, `crc(123)`, `crc("hello")` each raise `TypeError` with a message mentioning `bytes` |
| AC11 | Result is masked to 10 bits: `0 <= result < 1024` always |
| AC12 | Calling on 1MiB of random input completes in <2s on a 2020-class laptop (no quadratic blowup) |

The criteria are LOCKED at discovery time. The build phase may add tests but
must not relax or remove any criterion above.

---

## §4 Canonical Reference Implementation

```python
def crc(data: bytes) -> int:
    """CRC-10/GSM (3GPP TS 44.006). Pure-Python, ~20 LOC.

    Parameters per RevEng catalogue:
      width=10, poly=0x175, init=0x000,
      refin=false, refout=false, xorout=0x3FF, check=0x12A.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc10-gsm.crc() expected bytes-like, got {type(data).__name__}"
        )
    crc_reg = 0x000
    for byte in data:
        crc_reg ^= (byte << 2) & 0x3FF
        for _ in range(8):
            if crc_reg & 0x200:
                crc_reg = ((crc_reg << 1) ^ 0x175) & 0x3FF
            else:
                crc_reg = (crc_reg << 1) & 0x3FF
    return (crc_reg ^ 0x3FF) & 0x3FF
```

This is the verbatim RevEng pseudocode translated to Python with one explicit
bit-mask `& 0x3FF` on each update to guarantee the state never escapes the
10-bit window. The `(crc_reg ^ 0x3FF) & 0x3FF` finalisation guarantees the
returned value is in `[0, 1024)` (AC11).

The `TypeError` guard is up-front so badly-typed callers fail fast with a
useful message instead of `TypeError: 'int' object is not iterable` deep in
the loop (AC10).

---

## §5 Test Categories (≥100 pytest items expected)

1. **canonical_check** — RevEng check value for `"123456789"` (AC3), plus
   the 5 vectors in `seed_evidence.json`. Target: 6 tests.
2. **byte_range_zero** — `crc(bytes([n]))` for `n` in `0..255`. Target: 256 tests.
3. **length_sweep** — `crc(b"\x00" * n)` for `n` in `0..63`. Target: 64 tests.
4. **seed_vectors** — replay every vector from `seed_evidence.json` into
   one pytest item each. Target: 6 tests.
5. **determinism** — call `crc(random_input)` twice and assert equality on
   50 distinct random inputs. Target: 50 tests.
6. **type_errors** — `crc(None)`, `crc(0)`, `crc("x")`, `crc([1,2,3])`,
   `crc({"a":1})` — each must raise `TypeError` with `bytes` in the message.
   Target: 5 tests.
7. **oracle_differential** — vs `crcmod.mkCrcFun(0x175, rev=False,
   initCrc=0, xorOut=0x3FF)` on 200 random inputs of length 1..1000.
   Target: 200 tests.
8. **edge** — `crc(b"\x00"*0)`, `crc(b"\xff"*4096)`, `crc(b"\x00"*1_000_000)`
   (perf). Target: 5 tests.

Total target: ~592 tests. Floor of 100 strictly enforced by QA.

---

## §6 Out-of-Scope / Non-Goals

- **NOT cryptographic.** CRC-10/GSM is an error-detecting code, not a hash;
  collisions are routine and expected.
- **NOT optimised.** This is a reference implementation. A 10× speedup is
  trivially achievable with table-driven updates but is explicitly out of
  scope (would obscure the parameter-by-parameter correspondence to RevEng).
- **NOT cross-platform.** Python 3.10+ on CPython only. PyPy / GraalPy are
  not tested.
- **NOT a CRC suite.** Only CRC-10/GSM. Other widths (8/16/32) belong in
  other `crc*-pure` repos (78 already shipped, all RevEng-derived).
- **No `crcmod` polyfill.** If the user wants `crcmod`-style polymorphism
  they should `import crcmod` themselves; this module exports one function.

---

## §7 Dependencies & Constraints

- **Python** ≥ 3.10 (uses built-in `bytes`/`bytearray`/`memoryview` only).
- **`dependencies = []`** in `pyproject.toml`. No third-party at install
  time; no third-party at test time beyond `pytest` (dev-only).
- **Single public function** `crc(data: bytes) -> int`; everything else
  is private (leading underscore or module-private names).
- **No CLI** at v0.1.0. Library only.
- **No C extension.** Pure CPython bytecode.
- **No I/O.** Function in, int out — no `os`, no `pathlib`, no `socket`.

---

## §8 Honest Install + Verification

### 8.1 Install (when shipped, not at discover time)

Once the package is pushed to GitHub (cycle_131/post-discover phases),
users install via:

```
pip install git+https://github.com/prasad-a-abhishek/crc10-gsm-pure.git
```

(This is the pinned `pip install` form because `crc10-gsm` is NOT on PyPI
at v0.1.0. A future PyPI upload would change this string but at v0.1.0 the
GitHub URL is the only honest install command.)

### 8.2 Verify

```
python3 -c "from crc10_gsm import crc; print(hex(crc(b'123456789')))"
# expect: 0x12a
```

### 8.3 Test count claim

The README at ship time will claim a specific pytest count. That count
**must match `pytest --collect-only -q` output** at the same SHA. The QA
phase will run `pytest --collect-only` and paste its final-line tally into
`README.md` — no hand-typed numbers.

### 8.4 Limitations to state in README

The README must explicitly say:

- Pure-Python reference; not the fastest possible implementation.
- Single-algorithm; if you need multiple CRCs use `crcmod`.
- Not constant-time; do not use on attacker-controlled input requiring
  side-channel resistance.

These three sentences are an **invariant** of the shipped repo and the
QA gate refuses push if any is missing.
