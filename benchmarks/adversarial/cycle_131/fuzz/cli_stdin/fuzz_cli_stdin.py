#!/usr/bin/env python3
"""Atheris fuzz harness — cli_stdin surface: bytes read via --stdin path."""
import atheris
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../../../src"))

from crc10_gsm import crc


def test_one_input(data: bytes) -> None:
    """Simulate --stdin read path: raw bytes → crc() with no stripping."""
    # sys.stdin.buffer.read() returns raw bytes; nothing is stripped
    result = crc(data)
    assert 0 <= result < 1024


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
