# TEST_GAPS — crc10-gsm-pure (cycle_131)

> Gaps in the existing 1090-test suite as of commit fae2d56. The T2
> harness card will use this list to seed its fuzz inputs and the
> T4 triage card may add tests here. Every entry here was probed
> manually during the T1 audit; the entry's "Status" column reports
> the observed behaviour, not a desired behaviour.

## Existing coverage (1090 tests, 35 functions)

The suite is dominated by parameter sweeps over small inputs (256 + 256 +
128 + 50 + 50 + 60 + 256 = 1056) plus a handful of structural tests.
It is **strong on byte-level coverage and weak on stress and CLI surface
coverage**. The gaps below are the realistic attack surface the suite
does not exercise.

## Gap inventory

### G1 — 100 MiB / 1 GiB stress

| Aspect | Detail |
|---|---|
| Existing coverage | `test_edge_1mb_random` covers 1 MiB only (AC12 floor). |
| Gap | Nothing tests 10 MiB / 100 MiB / 1 GiB. The 100 MiB run completes in ~36 s; 1 GiB is ~6 min linear. |
| Why a gap | Library consumers hashing large files (think `crc10-gsm --stdin < capture.bin`) hit this path. A quadratic blowup would surface here long before it surfaces at 1 MiB. |
| Recommended test | `test_edge_100mb_random` — `crc(os.urandom(100_000_000))`, assert mask + determinism. Slow (~36 s) but high value. Skip in fast CI; mark `@pytest.mark.slow`. |
| Severity | Low — purely a performance regression guard. |

### G2 — CRLF in stdin

| Aspect | Detail |
|---|---|
| Existing coverage | `test_cli_stdin` uses `input=b"123456789"` (9 bytes, no newlines). |
| Gap | Nothing tests stdin with embedded `\n`, `\r\n`, or trailing newline. |
| Why a gap | Operators pipe text into `--stdin` via shell (`echo -n`, `cat file.txt | crc10-gsm --stdin`). A `\r\n`-terminated file is two bytes longer than its logical content. The library does NOT strip newlines — that is correct CRC semantics — but the test suite never locks that behaviour in. |
| Recommended test | `test_cli_stdin_with_newline` — feed `b"123456789\n"`, assert `crc(b"123456789\n") != 0x12A` and is masked. |
| Severity | Info. |

### G3 — Malformed `--data` / latin-1 fallback

| Aspect | Detail |
|---|---|
| Existing coverage | `test_cli_data_ascii` only. |
| Gap | Nothing tests `--data ZZZZ`, `--data xy`, `--data 1` (odd-length hex), `--data 31 32 && rm`. All of these silently fall back to the latin-1 fallback in `_parse_data`. |
| Why a gap | Behavioural surprise for operators. Not a vulnerability (no shell expansion happens — `subprocess.run([sys.executable, ...])` is used with an argv list, so no shell injection is possible). But the test suite documents no contract for what these inputs should do. |
| Recommended test | `test_cli_data_latin1_fallback` — `--data ZZZZ` should produce a deterministic result equal to `crc(b"ZZZZ") == crc(b"\x5a\x5a\x5a\x5a")` (lock the current behaviour). |
| Severity | Info. |

### G4 — `--self-test` / `--register` exit before reading stdin

| Aspect | Detail |
|---|---|
| Existing coverage | `--self-test` and `--register` are tested individually. |
| Gap | Nothing tests `--self-test --data 49 50 51` (mutually exclusive at runtime; `--self-test` wins). |
| Why a gap | Minor — argparse will silently ignore later positionals. Locks behaviour. |
| Recommended test | `test_cli_self_test_takes_precedence` — combined invocation should run self-test, NOT consume data. |
| Severity | Info. |

### G5 — Subclass of `bytes`

| Aspect | Detail |
|---|---|
| Existing coverage | `bytes`, `bytearray`, `memoryview` are tested. |
| Gap | A subclass of `bytes` (`class MyBytes(bytes): pass`) is NOT explicitly tested but `isinstance` accepts it (probed manually: returns 0x12A). |
| Why a gap | Users sometimes subclass bytes for typed wrappers. Documenting the accepted-set. |
| Recommended test | `test_subclass_of_bytes` — `class MyBytes(bytes): pass; assert crc(MyBytes(b"123456789")) == 0x12A`. |
| Severity | Info. |

### G6 — `array.array('B', …)` rejection

| Aspect | Detail |
|---|---|
| Existing coverage | None. |
| Gap | `crc(array.array('B', b'123456789'))` raises `TypeError` because `array.array` is not in the `(bytes, bytearray, memoryview)` whitelist. This is conservative — `array.array` IS iterable of int 0..255 — but the test suite does not pin the behaviour. |
| Why a gap | If a future maintainer widens the whitelist (to support `numpy` byte arrays or similar), the test suite will not catch it as a regression. |
| Recommended test | `test_array_array_raises` — `import array; with pytest.raises(TypeError): crc(array.array('B', b'123456789'))`. |
| Severity | Info. |

### G7 — Generator / iterator rejection

| Aspect | Detail |
|---|---|
| Existing coverage | None. |
| Gap | `crc(b'a' for _ in range(10))` raises `TypeError`. Generators are iterable but not bytes-like. |
| Why a gap | Same as G6 — pinning the whitelist. |
| Recommended test | `test_generator_raises_typeerror`. |
| Severity | Info. |

### G8 — Very large int (`2**1000`) rejection

| Aspect | Detail |
|---|---|
| Existing coverage | `test_typeerror_int` covers `123`. |
| Gap | `2**1000` is also an `int` and is correctly rejected. The test pins "small int" but not "huge int". |
| Why a gap | Trivial — same path, same result. |
| Recommended test | Optional — combine into `test_typeerror_int` as `crc(2**1000)` parametrization. |
| Severity | Info. |

### G9 — 8-bit bit-walk via single-byte inputs (already partially covered)

| Aspect | Detail |
|---|---|
| Existing coverage | `test_edge_single_bit` walks all 8 bit positions within a single byte — masked. |
| Gap | The test asserts `0 <= result < 1024` (mask) but does NOT pin the specific CRC for each bit position. A future algorithm regression that still produces masked-but-wrong values would not be caught. |
| Recommended test | Parametrize `test_bit_position_oracle` with the actual CRC of `bytes([1 << b])` for `b in range(8)`, computed once and locked. |
| Severity | Low. |

### G10 — Sub-byte input sizes (1, 2, 3 bits — synthetic)

| Aspect | Detail |
|---|---|
| Existing coverage | None — `bytes` are byte-aligned, so "1 bit" doesn't apply. |
| Gap | N/A — bytes cannot be smaller than 1 byte. |
| Severity | N/A. |

### G11 — `bytearray` mutation safety

| Aspect | Detail |
|---|---|
| Existing coverage | `test_bytearray_input_canonical` and `_empty`. |
| Gap | Neither test asserts that the input `bytearray` is NOT mutated by `crc`. Probed manually: confirmed not mutated (the loop reads ints, doesn't write). |
| Recommended test | `test_bytearray_not_mutated` — `b = bytearray(b"123456789"); crc(b); assert b == bytearray(b"123456789")`. |
| Severity | Info. |

### G12 — Cross-architecture CRC-10/ATM disambiguation (already done)

| Aspect | Detail |
|---|---|
| Existing coverage | QA report §8 includes a 7-row table comparing crc10-gsm vs crc10-atm-pure (cycle_114). |
| Gap | None — this was done in QA. Listed here for completeness. |
| Severity | — |

### G13 — CLI argument injection / shell metacharacters

| Aspect | Detail |
|---|---|
| Existing coverage | None. |
| Gap | Probed `--data "31;32"`, `--data "31|32"`, `--data "31 32 && rm"`. All produce a deterministic CRC of the latin-1 bytes (the metacharacters are literal data, not shell). The subprocess is invoked with an argv list, not a shell, so no injection is possible. |
| Recommended test | `test_cli_data_shell_metachars` — lock behaviour with a parametrized test. |
| Severity | Info. |

### G14 — `--help` exit

| Aspect | Detail |
|---|---|
| Existing coverage | None. |
| Gap | `python3 -m crc10_gsm --help` exits 0 (argparse default). Useful to lock. |
| Recommended test | `test_cli_help_exits_zero`. |
| Severity | Info. |

## Gap summary

| ID | Severity | Description |
|---|---|---|
| G1 | Low | 100 MiB stress test |
| G2 | Info | CRLF in stdin |
| G3 | Info | latin-1 fallback locking |
| G4 | Info | self-test/data precedence |
| G5 | Info | bytes subclass acceptance |
| G6 | Info | array.array rejection |
| G7 | Info | generator rejection |
| G8 | Info | big-int rejection |
| G9 | Low | bit-walk oracle pinning |
| G10 | N/A | sub-byte sizes (impossible) |
| G11 | Info | bytearray non-mutation |
| G12 | — | cross-cycle disambiguation (done in QA) |
| G13 | Info | shell metachar safety |
| G14 | Info | --help exit code |

**Critical gaps: 0.**
**High gaps: 0.**
**Medium gaps: 0.**
**Low gaps: 2** (G1, G9) — both are "test hardening", not security.
**Info gaps: 11** — documentation/locking tests; recommended for the T3
seed-corpus card to bake into the cycle's permanent test suite.
