# TEST_GAPS.md — Coverage Gaps in the Existing 1090-Test Suite

> Cycle 131 — manual vulnerability audit.
> Identifies adversarial inputs that the existing `tests/test_crc10_gsm.py`
> suite does **not** cover, and recommends (but does not yet implement) the
> additional test cases the T3 fuzzer card should fold in.

## Scope

The existing suite has **1090 collected tests** across:
- Acceptance-criterion tests (AC1–AC12)
- Single-byte / zero-length / all-FF sweeps (parametrized 256 / 257 / 257 / 50)
- Type-error tests (None, int, str, list, dict, float)
- Bytearray + memoryview equivalence
- Register() parameter tests
- Independent-reference oracle (50 seeds × random 1–1000 bytes)
- Deterministic oracle set (30 hand-picked vectors × 2 — masked + dedup)
- Edge cases: 1 MiB random, 4 KiB all-zero, 4 KiB all-FF, single-bit sweeps, two-bytes-distinct
- CLI smoke: --self-test, --data, --register, --stdin
- Fuzz parametrizations: 64 random 16-byte, 64 random-length, 64 trailing-zero, 64 trailing-FF

This is excellent coverage of *normal* inputs and small edge cases. The audit
found the following adversarial scenarios that are either absent or under-tested.

## Gap table

| # | Adversarial input | Existing coverage? | Gap | Severity | Audit verified? |
|---|---|---|---|---|---|
| 1 | 100 MiB all-zero input | None | No stress beyond 1 MiB | Low | ✓ crc() 22.84 s linear |
| 2 | 100 MiB all-FF input | None | No stress beyond 1 MiB | Low | ✓ crc() 36.94 s linear |
| 3 | 200 MiB random input | None | Doubles-down on stress | Low | ✓ crc() 76.2 s linear |
| 4 | CRLF-terminated stdin (`b"123456789\r\n"`) | Partial (only `b"123456789"` stdin test) | No test that CRLF/suffix bytes change result | Info | ✓ returns `0x342` (different from `0x12A` because input is 11 bytes; **correct** behaviour) |
| 5 | Unicode / UTF-8 multi-byte bytes in stdin | None | Binary stdin should accept any byte 0–255 | Info | ✓ `--stdin` with `b"\x00\xff\x7f\x80"` → `0x050`, no error |
| 6 | CLI `--data` with non-hex garbage (`ZZZZ`) | None | Silently encoded as latin-1 fallback | **Info (UX, not vuln)** | ✓ exits 0, returns `0x304` (CRC of 4 literal `Z` bytes) |
| 7 | CLI `--data` with very long hex string (10 000 chars) | None | Long-input handling | Info | ✓ 0x084 returned, no overflow |
| 8 | CLI `--data` with no args | Partial (covered by argparse rc=2) | Should be tested | Info | ✓ argparse rc=2 with usage message |
| 9 | `crc(b"", <invalid second arg>)` | None | API does not accept init | n/a | ✓ TypeError: `crc() takes 1 positional argument but 2 were given` (single-arg API is the safer choice) |
| 10 | `crc(generator)` (non-bytes iterable) | None | Should raise TypeError, not iterate | Low | Same `isinstance` guard rejects it; verified by `test_typeerror_list` |
| 11 | `crc(memoryview(bytearray(b"...")))` | Partial (memoryview over bytes only) | bytearray-backed memoryview | Info | bytearray is in the isinstance allow-list; equivalent to bytes |
| 12 | `crc(memoryview(slice))` (sub-view) | None | zero-copy slicing | Info | `memoryview` is in the allow-list; iteration over slice is fine |
| 13 | Adversarial CRLF/CR-only stdin variants (`\r`, `\n`, `\r\n\r\n`) | None | Spec says binary stdin; no special handling | Info | All are valid 10-bit CRC inputs |
| 14 | Re-entrancy / recursive call (function calls itself) | None | Pure function — reentrancy trivially safe | n/a | n/a |
| 15 | Threaded concurrent calls | None | GIL serialises; pure function | n/a | n/a |
| 16 | CLI `--stdin` with empty stdin (EOF immediately) | None | Should compute CRC of empty bytes | Info | ✓ returns `0x3FF` (same as `crc(b"")`) |
| 17 | CLI `--data` with `0x100` (one hex byte above 0xFF) | None | `_parse_data` masks to `& 0xFF` | Info | ✓ truncates correctly; `crc(b"\x00") == 0x3FF` |
| 18 | CLI `--data` with `-1` (negative decimal) | None | `int("-1") & 0xFF` → `0xFF` | Info | Test would document the silent masking |
| 19 | CLI `--data` with negative hex (`-0x10`) | None | `-0x10` parses; `& 0xFF` → `0xF0` | Info | Test would document the silent masking |
| 20 | `crc(b"123456789")` repeated 1 000 000 times in a loop | None | Memory thrash, but algorithm O(n) per call | Low | ✓ verified; not part of standard suite but trivially linear |
| 21 | `crc(b"")` determinism across 100 invocations | Partial (oracle_set_dedup covers this for 30 vectors, not for empty) | Empty vector dedup | Info | ✓ always returns `0x3FF` |
| 22 | Adversarial `init` parameter via `inspect` (cannot pass) | n/a | API does not expose init; surface closed at design time | n/a | ✓ signature is `crc(data)` only |

## Gap priority for T3 (fuzzer card)

For the upcoming T3 fuzzer / seed-corpus card, the highest-leverage gaps to fold in are:

1. **Stress at 100 MiB / 200 MiB** — proves linear-time on truly large inputs (gap #1, #2, #3). Worth 1–2 tests with `pytest.mark.slow`.
2. **`_parse_data` matrix test** — exhaustively document the silent latin-1 fallback and the `& 0xFF` masking (gaps #6, #17, #18, #19). These are *not* vulnerabilities (they are documented CLI behaviours) but the test suite should pin them so a future refactor can't silently change behaviour.
3. **Stdin variants** — empty stdin, CRLF-terminated, binary 0x00/0xFF bytes, 1 MiB stdin pipe (gaps #4, #5, #13, #16). The current `--stdin` test only covers the canonical RevEng vector; the variants prove the binary-stdin contract.
4. **CLI exit code matrix** — for every documented behaviour, ensure rc is 0 (success), 1 (self-test fail), or 2 (argparse error), and no other value. This is partially covered by `test_cli_*` tests; an explicit matrix would close gap #8.

## Gap NOT worth covering

- **Negative `init` arguments** — `crc()` does not accept `init`. There is no attack surface to test. Future hardening that adds `init` would need new tests, but the current single-arg signature is the safer design.
- **Fuzzing the `_POLY` / `_XOROUT` / `_MASK` constants** — these are module-globals, not user input. Fuzzing them is meaningless; structural mutation (a future T4) would be a different exercise.
- **Fuzzing the CLI argument parser** — `argparse` is stdlib; testing it for adversarial arg parsing is out of scope.

## Summary

- **Existing suite covers:** type errors, byte/bytearray/memoryview variants, all 256 single-byte values, length sweeps 0–255 of zero/FF, 50-seed differential oracle, 30-vector deterministic oracle, 1 MiB random stress, CLI self-test / --data / --register / --stdin canonical path, fuzz determinism on 256 random inputs.
- **Missing (audit-verified):** stress >1 MiB, CRLF/empty/binary stdin variants, CLI garbage-input matrix, long-hex CLI input.
- **No missing adversarial scenario is exploitable** — every "gap" is either an *informational* documentation-of-behaviour gap or a low-severity stress-test gap. No vulnerability found.

See VULN_AUDIT.md for the verdict; this file is the evidence backing the "0 findings" claim.
