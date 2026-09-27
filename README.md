# crc10-gsm

> **Pure-Python reference implementation of CRC-10/GSM (3GPP TS 44.006), zero runtime deps.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/crc10-gsm-pure.git
```

```python
from crc10_gsm import crc
print(hex(crc(b"123456789")))  # 0x12a
```

```bash
python3 -m crc10_gsm --self-test    # RevEng canonical check
python3 -m crc10_gsm --data 31 32 33 34 35 36 37 38 39   # 0x12a
```

## ⚡ Performance & Benchmarks

CRC-10/GSM operates over a 10-bit state — the inner loop processes 8 bit-iterations per
input byte. As a reference implementation we prioritize clarity over speed; a table-driven
variant (out of scope at v0.1.0) would be ~10× faster.

Measured throughput (`time.perf_counter()`, 50 iterations × 3 workloads, see
`benchmarks/BENCHMARK.md` for the full table):

| Workload                | Mean      | P95       |
|-------------------------|-----------|-----------|
| `b"A"` (1 B)            | ~0.7 µs   | ~1.0 µs   |
| `b"123456789"` (9 B)    | ~4.1 µs   | ~4.4 µs   |
| `os.urandom(1 MB)`      | ~359 ms   | ~362 ms   |

Run locally:

```bash
python3 benchmarks/run_benchmark.py
```

## Why crc10-gsm?

The standard Python CRC library `crcmod` covers CRC-10/GSM but bundles many widths
and optionally compiles a C extension at install time. For a protocol engineer
implementing a GSM/LAPDm decoder who needs **only** CRC-10/GSM and wants zero
runtime dependencies, `crcmod` is overkill:

- **Single-algorithm module**: `crc(data: bytes) -> int`, audit each RevEng parameter
  line-by-line against the catalogue.
- **Zero install dependencies**: pure CPython bytecode, works in Pyodide / Lambda / CI
  without compiling C.
- **Honest byte-exact output** against the RevEng canonical `0x12A` check value.

**Trade-off:** the bit-by-bit implementation is ~10× slower than a table-driven
variant or `crcmod`'s C extension. For high-throughput paths we recommend
`crcmod`; for verification, audit, and small payloads, `crc10-gsm` is sufficient.

## Key Features

- **Byte-exact** against RevEng canonical `0x12A` for `b"123456789"`.
- **Parameter-faithful** — width/poly/init/refin/refout/xorout match RevEng catalogue.
- **Type-safe** — non-bytes input raises `TypeError` with a clear message.
- **CLI** — `python3 -m crc10_gsm --self-test | --data ... | --stdin | --register`.
- **Zero runtime deps** — only `bytes`/`bytearray`/`memoryview` from stdlib.

### API

```python
from crc10_gsm import crc, register

# Compute CRC over bytes
crc(b"")              # 0x3FF
crc(b"123456789")     # 0x12A
crc(b"\x00" * 1024)   # deterministic 10-bit value

# Inspect RevEng parameter table
register()
# {'width': 10, 'poly': 0x175, 'init': 0x000,
#  'refin': False, 'refout': False, 'xorout': 0x3FF, 'check': 0x12A}
```

### CLI

```
python3 -m crc10_gsm --self-test
python3 -m crc10_gsm --data 31 32 33 34 35 36 37 38 39
python3 -m crc10_gsm --stdin < some_binary_blob
python3 -m crc10_gsm --register
```

## Limitations

- Pure-Python reference implementation; not the fastest possible.
- Single-algorithm; if you need multiple CRC widths use `crcmod`.
- Not constant-time; do not use on attacker-controlled input requiring side-channel resistance.
- Python 3.10+ on CPython only; PyPy / GraalPy untested.

## License

MIT License — Copyright (c) 2026 prasad-a-abhishek
