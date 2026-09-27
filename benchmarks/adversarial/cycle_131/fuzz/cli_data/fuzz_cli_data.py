#!/usr/bin/env python3
"""Atheris fuzz harness — cli_data surface: _parse_data + crc pipeline via direct import."""
import atheris
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../../../src"))

from crc10_gsm.__main__ import _parse_data
from crc10_gsm import crc


def test_one_input(data: bytes) -> None:
    """Parse raw bytes as a data-arg string and verify CRC output."""
    try:
        arg_str = data.decode("utf-8", errors="replace").rstrip("\x00\n\r")
    except Exception:
        return
    if not arg_str:
        return
    try:
        parsed = _parse_data([arg_str])
    except Exception:
        return  # malformed input is expected
    result = crc(parsed)
    assert 0 <= result < 1024


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
