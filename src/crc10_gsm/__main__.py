"""CLI for crc10-gsm: compute CRC-10/GSM over bytes from stdin or --data argument.

Usage:
    python3 -m crc10_gsm --data 31 32 33 34 35 36 37 38 39
    python3 -m crc10_gsm --self-test
    echo -n "123456789" | python3 -m crc10_gsm --stdin
"""
from __future__ import annotations

import argparse
import sys

from ._crc10_gsm import crc, register


def _parse_data(values: list[str]) -> bytes:
    """Parse list of hex strings (or integers) into bytes."""
    if not values:
        return b""
    if len(values) == 1 and len(values[0]) % 2 == 0:
        try:
            return bytes.fromhex(values[0])
        except ValueError:
            pass
    out = bytearray()
    for v in values:
        if v.startswith("0x"):
            out.append(int(v, 16) & 0xFF)
        else:
            try:
                out.append(int(v, 16) & 0xFF)
            except ValueError:
                try:
                    out.append(int(v) & 0xFF)
                except ValueError:
                    out.extend(v.encode("latin-1"))
    return bytes(out)


def _self_test() -> int:
    """Run the RevEng canonical check; exit 0 on pass, 1 on fail."""
    expected = 0x12A
    actual = crc(b"123456789")
    if actual != expected:
        print(f"FAIL: crc(b'123456789') = 0x{actual:03X}, expected 0x{expected:03X}", file=sys.stderr)
        return 1
    print(f"PASS: crc(b'123456789') = 0x{actual:03X}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint. Returns 0 on success, 1 on error."""
    p = argparse.ArgumentParser(
        prog="crc10-gsm",
        description="Pure-Python CRC-10/GSM (3GPP TS 44.006).",
    )
    p.add_argument("--data", nargs="+", default=[], help="bytes to CRC (hex or decimal)")
    p.add_argument("--stdin", action="store_true", help="read bytes from stdin")
    p.add_argument("--self-test", action="store_true", help="run RevEng canonical check")
    p.add_argument("--register", action="store_true", help="print RevEng parameter table")
    args = p.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.register:
        for k, v in register().items():
            print(f"{k}={v}")
        return 0
    if args.stdin:
        data = sys.stdin.buffer.read()
    else:
        data = _parse_data(args.data)

    print(f"0x{crc(data):03x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
