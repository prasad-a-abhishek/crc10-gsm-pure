"""CRC-10/GSM algorithm -- verbatim RevEng pseudocode (LSB-first, 10-bit state)."""
_MASK = 0x3FF
_POLY = 0x175
_XOROUT = 0x3FF


def crc(data: "bytes | bytearray | memoryview") -> int:
    """Compute CRC-10/GSM over `data` per 3GPP TS 44.006 §5.3.4.

    Parameters (RevEng catalogue):
        width=10, poly=0x175, init=0x000,
        refin=false, refout=false, xorout=0x3FF, check=0x12A.

    Returns the masked 10-bit CRC value in [0, 1024).

    Raises:
        TypeError: if `data` is not a bytes-like object.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc10_gsm.crc() expected bytes-like, got {type(data).__name__}"
        )
    crc_reg = 0x000
    for byte in data:
        crc_reg ^= (byte << 2) & _MASK
        for _ in range(8):
            if crc_reg & 0x200:
                crc_reg = ((crc_reg << 1) ^ _POLY) & _MASK
            else:
                crc_reg = (crc_reg << 1) & _MASK
    return (crc_reg ^ _XOROUT) & _MASK


def register() -> dict:
    """Return RevEng parameter table for the CRC-10/GSM algorithm."""
    return {
        "width": 10,
        "poly": _POLY,
        "init": 0x000,
        "refin": False,
        "refout": False,
        "xorout": _XOROUT,
        "check": 0x12A,
    }
