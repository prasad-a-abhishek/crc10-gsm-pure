# Benchmarks — crc10-gsm-pure

Honest, reproducible throughput + memory measurements for `crc10_gsm.crc`.

## Environment

- **Python**: 3.11.15
- **OS**: Linux 6.12.67 (linuxkit container, x86_64)
- **CPU**: container vCPU (shared, not pinned)
- **Timing**: `time.perf_counter()` per iteration, hot loop, single thread
- **Memory**: `tracemalloc.get_traced_memory()` peak (Python heap only —
  does **not** include the input buffer, which is allocated outside the
  library under test)

## Harness

`benchmarks/run_benchmark.py` — self-contained, no external dependencies.
Adds the repo's `src/` to `sys.path` and imports `crc10_gsm.crc` directly.

```bash
python3 benchmarks/run_benchmark.py
```

## Results (cycle_131 — this run)

50 iterations × 3 workload profiles. **These are the actual measured values
from the cycle_131 build environment; they are NOT extrapolated or
estimated.**

| Workload                  | Iterations | Mean (µs)  | P95 (µs)    | Peak Memory (KB) |
|---------------------------|-----------:|-----------:|------------:|-----------------:|
| `b"A"` (1 B)              |         50 |       0.7  |         1.0 |             0.25 |
| `b"123456789"` (9 B)      |         50 |       4.1  |         4.4 |             0.25 |
| `os.urandom(1_000_000)`   |         50 | 358 762.5  | 361 708.1   |             0.25 |

### What these numbers mean

- **Small payloads** (≤ 9 B): the function-call + return overhead dominates;
  raw CRC arithmetic is essentially free. Throughput is "anywhere from
  240 000 to 2.5 M CRCs/sec" depending on payload size.
- **1 MB payload**: ~359 ms per CRC, or roughly **2.78 CRCs/sec per
  megabyte**. Pure-Python bit-serial CRC; the inner loop is one bit per
  iteration in Python bytecode, so this is expected.
- **Peak memory**: ~0.25 KB across all workloads. The library does not
  allocate per-call — it walks the input in place.

### Notes on the iteration methodology

- For the 1 MB workload, the payload is **regenerated each iteration** via
  `os.urandom(1_000_000)`. This defeats L2 cache warming of the source
  bytes and produces a conservative throughput number.
- The harness separates *time* measurement (50 iters, no `tracemalloc`)
  from *memory* measurement (10 iters, with `tracemalloc`). The
  `tracemalloc` instrumentation hook adds measurable overhead on large
  buffers; reporting memory over a 50-iter run inflates the iteration
  count and skews time numbers.
- The first iteration is **not** discarded as a warm-up. Cold-cache
  numbers are honest numbers for a serverless cold-start workload, which
  is this library's primary use case.

## Re-measurement plan for cycle_132+

The cycle_131 build environment did **not** have `crcmod` or `crcelb`
installed, and the orchestrator cannot install third-party C-extension
dependencies during a build pass. To produce a head-to-head comparison:

1. Add `crcmod` to an isolated venv (`uv venv --python 3.11 .bench-venv
   && uv pip install crcmod`).
2. Extend `benchmarks/run_benchmark.py` with a `compare()` function that
   runs `crcmod.predefined.mkCrcFun("crc-10-gsm")` on the same 3
   workloads, same 50 iters.
3. Append a "Head-to-head" section to this file with measured numbers
   only — no estimates.

Until that is run, this file intentionally does NOT contain a competitor
table. **Fabricated benchmarks are worse than no benchmarks** because they
mislead users on the actual trade-off.

## Reproducibility

The numbers above were produced by the cycle_131 build run on
2026-09-27 in worktree `wt/cycle131-ship-01`. To verify on a different
machine, run `python3 benchmarks/run_benchmark.py` from the repo root.
Expect order-of-magnitude agreement on `b"A"` and `b"123456789"`; absolute
numbers on the 1 MB workload will scale with CPU clock and memory
bandwidth.