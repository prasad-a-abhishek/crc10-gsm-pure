# F-004 — No concurrent thread-safety test (Info)

- **Severity:** Info (defense-in-depth, test-coverage gap)
- **Surface:** #1 `crc()`
- **CWE:** CWE-1281 (Race Condition — Reference Count)
- **Origin:** cycle_131/adversary/01 VULN_AUDIT.md + TEST_GAPS.md G-14, G-15
- **T3 fuzzer status:** 95 iterations across 2 surfaces. 0 crashes, 0 mismatches.

## Failure mode (hypothetical)

`crc()` is a pure function with no shared mutable state. However, no test asserts
that concurrent calls from multiple threads are safe. CPython's GIL serialises
calls, but the absence of a test means a future change (e.g. adding a module-level
cache or mutable global) could introduce a race condition invisible to the suite.

## Why it is Info

- The current implementation has no shared mutable state.
- The GIL provides safety in CPython, but this is an implementation detail.
- No crash/hang was observed; this is a test-coverage gap, not a vulnerability.

## Recommendation

Add a test that exercises concurrent calls:
```python
from concurrent.futures import ThreadPoolExecutor
import numpy as np  # or generate random bytes

def test_thread_safety():
    seeds = [b"test_%d" % i for i in range(100)]
    results = list(ThreadPoolExecutor(max_workers=4).map(crc, seeds * 10))
    # Verify determinism: same input always gives same output
    for seed in seeds:
        expected = crc(seed)
        for _ in range(10):
            assert crc(seed) == expected
```

## Evidence

- `src/crc10_gsm/_crc10_gsm.py:7-31` — pure function, no globals
- `benchmarks/adversarial/cycle_131/VULN_AUDIT.md` §Surface 1
- `benchmarks/adversarial/cycle_131/TEST_GAPS.md` G-14, G-15
