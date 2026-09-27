"""crc10-gsm: pure-Python reference implementation of CRC-10/GSM (3GPP TS 44.006).

A 10-bit cyclic redundancy check used over GSM LAPDm radio frames.
Zero runtime dependencies; uses only `bytes`/`bytearray`/`memoryview` from stdlib.

Parameters per RevEng catalogue:
    width=10, poly=0x175, init=0x000, refin=false, refout=false, xorout=0x3FF, check=0x12A
"""
from ._crc10_gsm import crc, register

__version__ = "0.1.0"
__all__ = ["crc", "register"]
