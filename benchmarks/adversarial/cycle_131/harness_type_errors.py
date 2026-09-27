#!/usr/bin/env python3
"""Surface 1 (type-error boundary): pass non-bytes to crc() — must raise TypeError.

Validates Invariant 21 / AC12: crc() is TOTAL over arbitrary input and MUST NOT
raise ValueError or uncaught exceptions.  Instead, any non-bytes-like object
(None, int, str, list, dict, float, bool, tuple, set, complex, object) must
produce a clean TypeError with a descriptive message.

Stdlib-only.  Exit 0 = all TypeError, 1 = unexpected crash or wrong exception.
"""
from __future__ import annotations

import argparse
import sys
import time

sys.path.insert(0, "src")
from crc10_gsm import crc

MAX_ITERS = 100


def is_type_error_safe(exc: BaseException) -> bool:
    """Return True only if this is the exact TypeError crc() is specced to raise."""
    return (
        isinstance(exc, TypeError)
        and "expected bytes-like" in str(exc)
    )


BAD_INPUTS: list[tuple[str, object]] = [
    ("None",               None),
    ("int(0)",             int(0)),
    ("int(42)",            int(42)),
    ("str",                "hello"),
    ("str empty",          ""),
    ("list",               [1, 2, 3]),
    ("list empty",         []),
    ("dict",               {"a": 1}),
    ("float",              3.14),
    ("bool True",          True),
    ("bool False",         False),
    ("tuple",              (1, 2)),
    ("set",                {1, 2}),
    ("complex",            1 + 2j),
    ("object()",           object()),
]


def run(iters: int) -> int:
    """Run type-error suite. Return 0 on all-TypeError, 1 on any unexpected result."""
    crashes = 0
    t0 = time.monotonic()

    # 1. Curated bad inputs — each MUST raise TypeError cleanly
    for label, value in BAD_INPUTS:
        try:
            crc(value)  # type: ignore[arg-type]
            print(f"  FAIL {label}: no exception raised", file=sys.stderr)
            crashes += 1
        except TypeError as exc:
            if not is_type_error_safe(exc):
                print(f"  FAIL {label}: wrong TypeError message: {exc}", file=sys.stderr)
                crashes += 1
            # else: expected — OK
        except Exception as exc:
            print(f"  FAIL {label}: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
            crashes += 1

    # 2. Accept path: bytes-like objects MUST NOT raise
    good_inputs = [
        (b"",               "empty bytes"),
        (b"\x00",          "single zero byte"),
        (b"\xff",          "single 0xFF byte"),
        (b"123456789",     "canonical 9-byte"),
        (bytearray(b"test"), "bytearray"),
        (memoryview(b"view"), "memoryview"),
    ]
    for value, label in good_inputs:
        try:
            result = crc(value)  # type: ignore[arg-type]
            assert isinstance(result, int) and 0 <= result <= 0x3FF, f"bad result: {result}"
        except Exception as exc:
            print(f"  FAIL (accept path) {label}: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
            crashes += 1

    # 3. Random fuzz — find unexpected input-validation holes
    import random
    rng = random.Random(42)
    choices = [None, 0, 123, [], {}, 3.14, set(), tuple(), object(), "str"]
    for _ in range(iters):
        # Pick random non-bytes object
        obj = rng.choice(choices)
        try:
            crc(obj)  # type: ignore[arg-type]
            print(f"  FAIL random non-bytes: no exception for {type(obj).__name__}", file=sys.stderr)
            crashes += 1
        except TypeError:
            pass  # expected
        except Exception as exc:
            print(f"  FAIL random non-bytes: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
            crashes += 1

    dt = time.monotonic() - t0
    return crashes


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harness_type_errors: type-error boundary for crc()")
    ap.add_argument("--iters", type=int, default=MAX_ITERS)
    args = ap.parse_args()

    crashes = run(args.iters)
    print(f"[type_errors] iters={args.iters} crashes={crashes}")
    sys.exit(1 if crashes else 0)
