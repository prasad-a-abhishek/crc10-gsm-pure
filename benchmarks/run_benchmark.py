#!/usr/bin/env python3
"""crc10-gsm-pure benchmarks — 50 iterations × 3 workload profiles.

Self-contained: imports directly from src/, measures throughput + peak
memory. No external deps.

Methodology:
- Throughput: 50 iterations per workload, ``time.perf_counter`` per iter.
- Peak memory: 10 iterations with ``tracemalloc`` (the allocator hook
  itself adds non-trivial overhead on large buffers, so we keep this
  measurement short and report the maximum observed).
- For 1 MB workloads, the payload is re-generated each iteration to
  defeat L1/L2 cache warming of the source bytes.
- The harness is single-threaded and runs in-process with the library
  under test (no subprocess overhead), so numbers are tight.

Replication:
    python3 benchmarks/run_benchmark.py
"""
from __future__ import annotations

import gc
import os
import statistics
import sys
import time
import tracemalloc

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_SRC = os.path.join(_REPO, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from crc10_gsm import crc  # noqa: E402

TIME_ITERS = 50
MEM_ITERS = 10  # keep short — tracemalloc hook itself slows large iterations


def measure_time(fn, payload_factory, iters: int = TIME_ITERS) -> list[float]:
    """Pure wall-clock measurement, no tracemalloc. Returns list of seconds."""
    times: list[float] = []
    for _ in range(iters):
        payload = payload_factory()
        # No gc.collect: this is throughput-bound and we want a hot loop.
        t0 = time.perf_counter()
        fn(payload)
        times.append(time.perf_counter() - t0)
    return times


def measure_mem(fn, payload_factory, iters: int = MEM_ITERS) -> int:
    """Sample peak traced memory across ``iters`` calls. Returns max peak (bytes)."""
    peaks: list[int] = []
    for _ in range(iters):
        payload = payload_factory()
        gc.collect()
        tracemalloc.start()
        fn(payload)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return max(peaks)


def make_1mb() -> bytes:
    return os.urandom(1_000_000)


def make_static(payload: bytes):
    def f() -> bytes:
        return payload
    return f


def summarize(name: str, payload_factory) -> dict:
    times = measure_time(crc, payload_factory)
    peak_bytes = measure_mem(crc, payload_factory)
    mean_us = statistics.mean(times) * 1e6
    p95_us = sorted(times)[int(0.95 * len(times))] * 1e6
    return {
        "name": name,
        "iters": len(times),
        "mean_us": mean_us,
        "p95_us": p95_us,
        "peak_kb": peak_bytes / 1024.0,
    }


WORKLOADS = [
    ("b'A' (1 B)",         make_static(b"A")),
    ("b'123456789' (9 B)", make_static(b"123456789")),
    ("os.urandom(1 MB)",   make_1mb),
]


def main() -> int:
    print(f"{'workload':30s} {'mean (us)':>12s} {'p95 (us)':>12s} {'peak (KB)':>12s}")
    print("-" * 70)
    for name, factory in WORKLOADS:
        r = summarize(name, factory)
        print(f"{r['name']:30s} {r['mean_us']:12.1f} {r['p95_us']:12.1f} {r['peak_kb']:12.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())