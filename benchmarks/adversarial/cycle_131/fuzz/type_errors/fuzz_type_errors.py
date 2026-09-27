#!/usr/bin/env python3
"""Atheris fuzz harness — type_errors surface: TypeError for bad crc() inputs."""
import atheris
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../../../src"))

from crc10_gsm import crc


# Deterministic bad-type pool
_BAD_TYPES = [None, 0, "", [], {}]


def test_one_input(data: bytes) -> None:
    """Pass bad-type objects to crc() and verify TypeError is raised."""
    idx = data[0] % len(_BAD_TYPES) if data else 0
    bad = _BAD_TYPES[idx]

    raised = False
    try:
        crc(bad)  # type: ignore
    except TypeError:
        raised = True
    except Exception as e:
        raise AssertionError(f"crc() raised non-TypeError: {type(e).__name__}: {e}")

    assert raised, f"crc({type(bad).__name__!r}) did not raise TypeError"


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
