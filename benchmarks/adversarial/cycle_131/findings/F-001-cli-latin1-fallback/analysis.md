# F-001 — CLI latin-1 fallback behaviour not pinned in test suite (Info)

- **Severity:** Info (defense-in-depth, test-coverage gap)
- **Surface:** #4 CLI / `_parse_data`
- **CWE:** CWE-20 (Improper Input Validation)
- **Origin:** cycle_131/adversary/01 VULN_AUDIT.md (single Info finding) + TEST_GAPS.md G-6
- **T3 fuzzer status:** 95 iterations across 2 surfaces. 0 crashes, 0 mismatches.

## Failure mode (hypothetical)

`src/crc10_gsm/__main__.py:36` falls back to `v.encode("latin-1")` when
hex/decimal parsing fails. `--data ZZZZ` silently produces `[0x5A, 0x5A, 0x5A, 0x5A]`
and exits 0. A future refactor could silently change this fallback behaviour
(e.g., raising an exception instead, or switching to UTF-8), and the existing
test suite would not catch it.

## Why it is Info, not Low

- The latin-1 fallback is intentional documented behaviour (`--help` says "hex or decimal").
- No security boundary is bypassed — the function is pure and deterministic.
- A developer who accidentally changes the fallback would be visible in a diff.

## Recommendation

Add a test that explicitly asserts the latin-1 fallback output:
```python
def test_cli_data_latin1_fallback():
    result = subprocess.run([sys.executable, "-m", "crc10_gsm", "--data", "ZZZZ"],
                           capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == "0x304"  # CRC of b"ZZZZ" (0x5A * 4)
```

## Evidence

- `src/crc10_gsm/__main__.py:36` — latin-1 fallback
- `benchmarks/adversarial/cycle_131/VULN_AUDIT.md` §Info
- `benchmarks/adversarial/cycle_131/TEST_GAPS.md` G-6
