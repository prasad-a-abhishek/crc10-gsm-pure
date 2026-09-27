# F-003 — No stdin binary-variant test (CRLF, binary bytes, empty) (Info)

- **Severity:** Info (defense-in-depth, test-coverage gap)
- **Surface:** #4 CLI / `--stdin`
- **CWE:** CWE-20 (Improper Input Validation)
- **Origin:** cycle_131/adversary/01 VULN_AUDIT.md + TEST_GAPS.md G-4, G-5, G-13, G-16
- **T3 fuzzer status:** 95 iterations across 2 surfaces. 0 crashes, 0 mismatches.

## Failure mode (hypothetical)

`--stdin` reads raw bytes via `sys.stdin.buffer.read()`. TEST_GAPS gaps #4, #5,
#13, #16 document that CRLF-terminated, binary-byte, and empty stdin variants were
verified live by the auditor but no test asserts them. A future change to the
`--stdin` path (e.g. accidentally adding `.decode("utf-8")`) would not be caught.

## Why it is Info

- `--stdin` correctly passes raw bytes to `crc()` — verified by auditor.
- No error on binary input (0x00–0xFF all accepted).
- The current test only covers the canonical RevEng vector `b"123456789"`.

## Recommendation

Add a test that pipes binary variants to `--stdin` and asserts the correct CRC:
```python
import subprocess, sys

def test_stdin_binary_contract():
    # CRLF input
    r = subprocess.run([sys.executable, "-m", "crc10_gsm", "--stdin"],
                      input=b"123456789\r\n", capture_output=True)
    assert r.returncode == 0
    assert r.stdout.strip() == "0x342"  # CRC of 11 bytes

    # Binary bytes
    r = subprocess.run([sys.executable, "-m", "crc10_gsm", "--stdin"],
                      input=b"\x00\xff\x7f\x80", capture_output=True)
    assert r.returncode == 0
    assert r.stdout.strip() == "0x050"

    # Empty stdin
    r = subprocess.run([sys.executable, "-m", "crc10_gsm", "--stdin"],
                      input=b"", capture_output=True)
    assert r.returncode == 0
    assert r.stdout.strip() == "0x3ff"
```

## Evidence

- `src/crc10_gsm/__main__.py:70` — `sys.stdin.buffer.read()`
- `benchmarks/adversarial/cycle_131/VULN_AUDIT.md` §Surface 3
- `benchmarks/adversarial/cycle_131/TEST_GAPS.md` G-4, G-5, G-13, G-16
