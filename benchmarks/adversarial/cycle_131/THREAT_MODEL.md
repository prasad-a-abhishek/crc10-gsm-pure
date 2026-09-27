# THREAT_MODEL — crc10-gsm-pure (cycle_131)

> Narrative threat model for the T1 VULN_AUDIT. We enumerate attacker
> capabilities, assets, and worst-case impacts, then trace each
> capability to a concrete code path and a verdict.

## 1. Asset model

A pure-Python CRC library's only asset is **the CRC value returned to the
caller**. CRCs are not secrets — they are public by construction — so the
attacker is not trying to steal data. The attacker is trying to:

1. **Make the library return the wrong CRC** for a given input (silent
   correctness loss — a downstream radio-frame parser accepts a corrupt
   frame).
2. **Make the library crash, hang, or OOM** so a downstream tool that
   processes attacker-controlled bytes (e.g. a network capture processor)
   becomes a denial-of-service vector.
3. **Achieve code execution** via injection (eval, shell, pickle, etc.).

The downstream impact of (1) is a dropped or misclassified radio frame.
The downstream impact of (2) is a hung/failed protocol stack. The
downstream impact of (3) is arbitrary code execution on the host running
the library.

## 2. Attacker model

### 2.1 Attacker A — passive radio adversary

| Aspect | Detail |
|---|---|
| Capability | Can transmit arbitrary bytes over the GSM radio interface that the protocol stack will CRC-validate before acting on. |
| Goal | Produce a CRC mismatch that causes a frame drop, or match a CRC to inject a forged frame. |
| Realistic? | Yes — that's what CRC-10/GSM is designed to detect. |
| Library's role | The library is called on a frame whose contents include attacker-controllable bits. The attacker CAN choose bytes that yield any desired CRC after exhaustive search (1024 possible CRCs, 256^n possible inputs of length n). |
| What this means | The CRC is NOT a security boundary. It is an integrity check against **random** transmission errors, not against an active adversary. This is documented in `SPEC.md §6` (NOT cryptographic, NOT a hash) and in `README.md` "Limitations". |
| Verdict | **Not in scope for the audit.** The library's role is "compute CRC correctly"; making the CRC adversarial-secure is mathematically impossible for any 10-bit code. |

### 2.2 Attacker B — host-side attacker controlling CLI input

| Aspect | Detail |
|---|---|
| Capability | Can invoke `crc10-gsm --data …` or `… --stdin` with arbitrary bytes. |
| Goal | (a) Hang the process, (b) consume excessive memory, (c) achieve shell injection. |
| Realistic? | Yes — if the CLI is exposed as a subprocess of a larger tool that processes untrusted input. |
| What this audit checks | Memory growth (linear vs quadratic), stdin buffering (no `--max-bytes`), shell injection (argv-list vs shell-string). |
| Verdict | **In scope.** Findings addressed below. |

### 2.3 Attacker C — caller of the `crc()` Python API

| Aspect | Detail |
|---|---|
| Capability | Can call `crc(data)` with any Python object. |
| Goal | Cause a TypeError that is silently swallowed, produce a wrong CRC, or crash. |
| Realistic? | Yes — internal callers (e.g. a parser dispatching on input type) may pass non-bytes-like values. |
| What this audit checks | The TypeError is raised with a useful message (AC10), and the library does NOT silently coerce strings/lists to bytes. |
| Verdict | **In scope. AC10 already enforces this — confirmed.** |

### 2.4 Attacker D — supply-chain (zero-runtime-deps)

| Aspect | Detail |
|---|---|
| Capability | Inject malicious code via a runtime dependency. |
| Goal | Arbitrary code execution at import time. |
| Realistic? | N/A — `dependencies = []`. |
| Verdict | **Out of scope; not exploitable.** |

## 3. Worst-case impact analysis

For each attacker capability, the worst-case impact is:

| Attacker | Capability | Worst-case impact | Likelihood |
|---|---|---|---|
| A (radio) | Choose input bytes to forge a CRC | Frame misclassification downstream | Medium (mathematically inevitable for any 10-bit CRC) |
| B (CLI) | Pipe 1 GB into `--stdin` | Process consumes ~6 min CPU + 1 GB RAM | Medium (depends on tool exposure) |
| B (CLI) | `--data "; rm -rf /"` | Process interprets it as latin-1 bytes; no shell invocation | High (input space) but **no impact** |
| C (API) | `crc(None)` | TypeError with `bytes` in message; caller catches or fails fast | High (input space) but **no impact** |
| C (API) | `crc(2**100)` (huge int) | TypeError; same as above | High but **no impact** |
| D (supply chain) | Inject dep | N/A — no deps | N/A |

## 4. Per-surface threat trace

### 4.1 `crc(data)` Python API

| Threat | Mitigation | Residual risk |
|---|---|---|
| Non-bytes-like input | `isinstance` guard at line 19 | None — AC10 LOCKED |
| Integer overflow / OOB read | N/A in Python; iteration bounds-checks | None |
| Quadratic blowup | `for byte in data` is O(n); inner bit loop is constant 8 | None — AC12 LOCKED |
| Side-channel (timing) | Not constant-time; documented in README "Limitations" | Info — caller must not use this for attacker-time-sensitive contexts |
| State leak across calls | `crc_reg = 0x000` is local; no `global`/closure | None |

### 4.2 `register()` accessor

| Threat | Mitigation | Residual risk |
|---|---|---|
| Mutation of returned dict | Returns a fresh dict each call | None |
| Caller-supplied input | None accepted | None |

### 4.3 `--data` CLI flag

| Threat | Mitigation | Residual risk |
|---|---|---|
| Shell injection via `--data "31; rm -rf /"` | `subprocess.run([...])` uses argv-list; the semicolon is data | None |
| Malformed hex (`--data ZZZZ`) | latin-1 fallback consumes it; deterministic CRC | Info — silent behaviour |
| Empty `--data` | Returns `crc(b"") == 0x3FF` | None |
| `0x` prefix | Stripped in `_parse_data` line 27 | None |
| Decimal input | `int(v) & 0xFF` on fallback | None |

### 4.4 `--stdin` CLI flag

| Threat | Mitigation | Residual risk |
|---|---|---|
| Unbounded stdin | `sys.stdin.buffer.read()` reads all bytes into memory | **Info** — caller controls exposure; documented as filter-style CLI |
| Binary nulls / CRLF / unicode | `read()` returns raw bytes; algorithm is byte-oriented | None |
| Hang on closed pipe | Not handled — would raise `BrokenPipeError` to stderr | None |

### 4.5 `--self-test` CLI flag

| Threat | Mitigation | Residual risk |
|---|---|---|
| None | No user input | None |

### 4.6 `--register` CLI flag

| Threat | Mitigation | Residual risk |
|---|---|---|
| None | No user input | None |

## 5. Threat-model summary

The library is a textbook reference implementation: small surface, zero
runtime dependencies, no I/O, no shelling out, no dynamic code. The only
realistic attack surfaces are:

1. **DoS via large stdin** (Info) — documented linear behaviour; standard
   filter-CLI contract; not fixable without breaking the use case.
2. **Caller misuse (passing non-bytes-like)** (None — already mitigated
   with a clear TypeError, AC10).
3. **Algorithmic confusion with sibling CRC-10/ATM** (None — covered in
   QA report §8; the two algorithms produce distinct CRCs on every test
   input).

No Critical, High, or Medium findings. Two Info-level observations
(unbounded stdin and the latin-1 fallback in `--data`) are documented but
do not warrant code changes for v0.1.0.
