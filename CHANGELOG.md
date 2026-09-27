# Changelog — crc10-gsm

## 0.1.0 (cycle_131)

- Initial release.
- Pure-Python CRC-10/GSM (3GPP TS 44.006) reference implementation.
- Zero runtime dependencies.
- 1090 pytest items across 13 categories (collected by `pytest --collect-only -q`).
- CLI: `--self-test`, `--data`, `--stdin`, `--register`.
- Verified byte-exact against RevEng canonical `0x12A`.
- Independent pure-Python reference oracle differential (50 random inputs).
