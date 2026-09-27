#!/usr/bin/env python3
"""Atheris fuzz harness — crc_register surface: register() output sanity."""
import atheris
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../../../src"))

from crc10_gsm import crc, register


def test_one_input(_data: bytes) -> None:
    """register() returns a consistent dict — no user input affects it."""
    reg = register()
    # 1. Must be dict
    assert isinstance(reg, dict), f"register() returned non-dict: {type(reg)}"
    # 2. Canonical fields
    assert reg["width"] == 10
    assert reg["poly"] == 0x175
    assert reg["init"] == 0x000
    assert reg["refin"] is False
    assert reg["refout"] is False
    assert reg["xorout"] == 0x3FF
    assert reg["check"] == 0x12A
    # 3. crc(b"123456789") == check
    assert crc(b"123456789") == 0x12A


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
