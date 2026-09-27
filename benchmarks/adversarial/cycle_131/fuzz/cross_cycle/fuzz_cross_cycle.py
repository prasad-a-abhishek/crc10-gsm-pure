#!/usr/bin/env python3
"""Atheris fuzz harness — cross_cycle surface: oracle differential across iterations."""
import atheris
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../../../src"))

from crc10_gsm import crc

# Independent reference implementation for oracle differential
def _reference_crc(data: bytes) -> int:
    """Reference CRC-10/GSM implementation (same algorithm, written independently)."""
    _MASK = 0x3FF
    _POLY = 0x175
    _XOROUT = 0x3FF
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("expected bytes-like")
    crc_reg = 0x000
    for byte in data:
        crc_reg ^= (byte << 2) & _MASK
        for _ in range(8):
            if crc_reg & 0x200:
                crc_reg = ((crc_reg << 1) ^ _POLY) & _MASK
            else:
                crc_reg = (crc_reg << 1) & _MASK
    return (crc_reg ^ _XOROUT) & _MASK


def test_one_input(data: bytes) -> None:
    """Compare main and reference implementations — they must agree."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return

    main_result = crc(data)
    ref_result = _reference_crc(data)

    assert main_result == ref_result, (
        f"Oracle mismatch: crc()={main_result}, _reference_crc()={ref_result}, "
        f"data_len={len(data)}"
    )

    # Also verify check vector
    if data == b"123456789":
        assert main_result == 0x12A


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
