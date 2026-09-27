# F-002 — No >=1 MB stress test asserting bounded compute time (Info)

- **Severity:** Info (defense-in-depth, test-coverage gap)
- **Surface:** #1 `crc()`
- **CWE:** CWE-400 (Improper Resource Consumption)
- **Origin:** cycle_131/adversary/01 VULN_AUDIT.md + TEST_GAPS.md G-1, G-2, G-3
- **T3 fuzzer status:** 95 iterations across 2 surfaces. 0 crashes, 0 mismatches.

## Failure mode (hypothetical)

The longest input tested in `tests/test_crc10_gsm.py` is 1 MiB. CWE-400
(resource exhaustion) is not tested at scale. While VULN_AUDIT verified live that
100 MiB all-zero input completes in 22.84s (linear), 100 MiB all-FF in 36.94s,
and 200 MiB random in 76.2s, no unit test pins this bound.

## Why it is Info, not Low

- Algorithm is provably O(n) — each byte triggers exactly 8 constant-time iterations.
- VULN_AUDIT live verification confirmed linear scaling up to 200 MiB.
- No input can cause exponential blow-up; loop bounds are fixed.

## Recommendation

Add a `pytest.mark.slow` stress test:
```python
@pytest.mark.slow
def test_large_input_bounded_time():
    import time
    data = b"\x00" * (100 * 1024 * 1024)
    start = time.perf_counter()
    crc(data)
    elapsed = time.perf_counter() - start
    assert elapsed < 30  # linear bound: 100 MiB should finish in <30s
```

## Evidence

- `src/crc10_gsm/_crc10_gsm.py:23-31` — 8-iteration inner loop
- `benchmarks/adversarial/cycle_131/VULN_AUDIT.md` §Stress verification
- `benchmarks/adversarial/cycle_131/TEST_GAPS.md` G-1, G-2, G-3
