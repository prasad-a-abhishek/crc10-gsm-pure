# F-005 — CLI `_parse_data` silent `& 0xFF` masking not pinned in tests (Info)

- **Severity:** Info (defense-in-depth, test-coverage gap)
- **Surface:** #4 CLI / `_parse_data`
- **CWE:** CWE-20 (Improper Input Validation)
- **Origin:** cycle_131/adversary/01 VULN_AUDIT.md + TEST_GAPS.md G-17, G-18, G-19
- **T3 fuzzer status:** 95 iterations across 2 surfaces. 0 crashes, 0 mismatches.

## Failure mode (hypothetical)

`_parse_data` silently masks parsed integers to a single byte via `& 0xFF` at
`__main__.py:28,31,34`. `int("-1") & 0xFF = 0xFF`, `-0x10 & 0xFF = 0xF0`,
`0x100 & 0xFF = 0x00`. No test in the suite pins this masking behaviour. A future
refactor that removes the mask (e.g. to allow values >255) would silently change
outputs without a test catching it.

## Why it is Info

- The masking is intentional (CLI is documented as accepting bytes, not arbitrary ints).
- No error is raised; the CLI silently truncates.
- No security boundary is bypassed — CRC of truncated byte is still deterministic.

## Recommendation

Add a test matrix documenting the masking:
```python
def test_parse_data_masking():
    """int() values above 255 or below 0 are silently masked to & 0xFF."""
    # Test via CLI to exercise the full path
    cases = [
        ("0x100", b"\x00"),    # 256 & 0xFF = 0
        ("255", b"\xff"),
        ("-1", b"\xff"),       # -1 & 0xFF = 255
        ("-0x10", b"\xf0"),   # -16 & 0xFF = 240
    ]
    for arg, expected_byte in cases:
        r = subprocess.run([sys.executable, "-m", "crc10_gsm", "--data", arg],
                          capture_output=True, text=True)
        assert r.returncode == 0
        assert crc(expected_byte) == int(r.stdout.strip(), 16)
```

## Evidence

- `src/crc10_gsm/__main__.py:28,31,34` — `& 0xFF` masking
- `benchmarks/adversarial/cycle_131/VULN_AUDIT.md` §Surface 3
- `benchmarks/adversarial/cycle_131/TEST_GAPS.md` G-17, G-18, G-19
