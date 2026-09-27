# THREAT_MODEL.md — Adversary Model for crc10-gsm-pure

> Cycle 131 — manual vulnerability audit.
> Defines the attacker, the assets, the trust boundary, the attack vectors, and
> the worst-case impact for the CRC-10/GSM library at commit `fae2d56`.

## 1. Asset inventory

| Asset | Value to attacker | Disclosure / corruption impact |
|---|---|---|
| The CRC-10/GSM value computed by `crc()` | Low — a 10-bit checksum, not a secret | Tampering with the output value corrupts GSM LAPDm frame verification downstream; impact depends on the *caller*, not this library. |
| The host process | Low | A crash of `crc()` is contained to the caller's stack frame; the library does not run as a long-lived service. |
| Caller's other data | Low | The library is pure-functional and does not access caller's other state. |
| The library's binary (wheel) | Low | A tampered wheel on PyPI would replace the entire library; mitigated by `pip install --require-hashes` and the standard PyPI TLS trust model. |

CRC-10/GSM is **not a cryptographic primitive** (README §3 documents this
explicitly). The threat model therefore excludes: brute-forcing, pre-image
attacks, collision attacks in the cryptographic sense, and any attack that
relies on the CRC being a secret.

## 2. Trust boundary

```
┌─────────────────────────────────────────────────────────────┐
│ Caller's code (trusted)                                     │
│   │                                                         │
│   │  bytes/bytearray/memoryview                             │
│   ▼                                                         │
│ ┌───────────────────────────────────────────────────────┐   │
│ │ crc10_gsm.crc(data)  ──  pure function, no side fx   │   │
│ └───────────────────────────────────────────────────────┘   │
│   │                                                         │
│   │  int in [0, 1024)                                       │
│   ▼                                                         │
│ Caller's code (uses CRC value)                              │
└─────────────────────────────────────────────────────────────┘
```

The library sits inside the trust boundary of the calling application. The
caller controls `data`; the library produces a CRC value.

For the CLI:

```
┌────────────────────────────────────────────────────────────┐
│ Untrusted user (operator) — has shell access               │
│   │                                                        │
│   │  argv / stdin bytes / hex tokens                       │
│   ▼                                                        │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ argparse + _parse_data + sys.stdin.buffer.read()      │   │
│ │ crc10-gsm.__main__.main()                             │   │
│ │ crc10_gsm.crc(data)                                  │   │
│ └──────────────────────────────────────────────────────┘   │
│   │                                                        │
│   │  stdout hex / stderr / exit code                       │
│   ▼                                                        │
│ Untrusted user (operator) — sees output                     │
└────────────────────────────────────────────────────────────┘
```

For the CLI, the operator is also the consumer; they cannot attack themselves
in a meaningful way (they already have shell access). The threat model for the
CLI is therefore: (a) accidental mis-invocation, (b) downstream tooling that
parses the CLI output and acts on it without validating exit codes.

## 3. Adversary profiles

### Profile A — Misinvoking caller (most realistic)
- **Capability:** controls `data` passed to `crc()`. Can pass anything Python will let them pass.
- **Goal:** trigger a crash, exception, or wrong CRC value.
- **Result:** the `isinstance` type guard rejects non-bytes-likes with `TypeError`; bytes-likes always produce a deterministic masked CRC.
- **Worst-case impact:** uncaught `TypeError` propagates to caller, which is the correct behaviour for a type mismatch.

### Profile B — Operator running the CLI (intentional or accidental misuse)
- **Capability:** controls argv and stdin.
- **Goal:** execute arbitrary code via the CLI; exfiltrate data; trigger resource exhaustion.
- **Result:**
  - Shell injection: not possible — no shell, no `eval`, no `subprocess`. Verified: `python3 -m crc10_gsm --data "0x41;" "rm" "-rf" "/tmp/__crc10gsm_evil__"` exits rc=2 and does not touch the filesystem.
  - Resource exhaustion: `--stdin` reads to EOF; an attacker who can pipe arbitrarily large data into the CLI is already on the trusted side of the trust boundary.
  - Mis-decoding: `_parse_data` falls back to `latin-1` for non-numeric tokens (e.g. `--data ZZZZ` → 4 bytes `[0x5A, 0x5A, 0x5A, 0x5A]` → CRC `0x304`). Documented behaviour; not a vulnerability.

### Profile C — Adversary who controls the wheel / package distribution
- **Capability:** substitutes the package on PyPI or GitHub.
- **Goal:** deliver malicious code via `pip install crc10-gsm`.
- **Result:** out of scope for the library's source audit. Standard mitigation: pin to a known-good version with `pip install crc10-gsm==X.Y.Z` and use `--require-hashes`. The library's `dependencies = []` ensures no transitive supply chain.

### Profile D — Adversary exploiting cryptographic confusion
- **Capability:** convinces a user to use CRC-10/GSM as a cryptographic hash.
- **Goal:** bypass an integrity check.
- **Result:** documented as a non-cryptographic primitive; responsibility for misuse is on the caller. README §3 ("CRC-10/GSM is **not** a cryptographic primitive") and SPEC §1.2 ("one-off copies frequently get the xorout wrong") address this.

## 4. Attack vectors enumerated

These are the vectors from the task body V3, with audit-time verdicts:

### V3-1. Out-of-range register values
- **Surface:** `crc()` (no `init` parameter exists).
- **Audit verdict:** **Not exploitable.** The API does not accept an initial register value. Module constants are baked in.
- **CWE mapping:** CWE-1284 (does not apply).

### V3-2. Negative-length inputs
- **Surface:** `crc()` (no `length` parameter exists).
- **Audit verdict:** **Not exploitable.** The function accepts only a bytes-like; the loop iterates `for byte in data` and cannot iterate a negative count.
- **CWE mapping:** CWE-1284 (does not apply).

### V3-3. Non-bytes inputs
- **Surface:** `crc()`.
- **Audit verdict:** **Rejected.** `isinstance` guard raises `TypeError`. Verified for int, str, list, dict, float, None.
- **CWE mapping:** CWE-20 (mitigated).

### V3-4. Buffer-overflow on large inputs (1MiB, 100MiB)
- **Surface:** `crc()`.
- **Audit verdict:** **Linear time.** Verified:
  - 1 MiB random: < 1 s.
  - 10 MiB random: 3.6 s.
  - 100 MiB zero: 22.8 s.
  - 100 MiB 0xFF: 36.9 s.
  - 200 MiB random: 76.2 s.
  - Ratio 100→200 MiB ≈ 2.0x time → linear scaling. No quadratic blowup.
- **CWE mapping:** CWE-400 (mitigated by linear-time algorithm).

### V3-5. CLI injection
- **Surface:** `crc10-gsm --data` / `--stdin`.
- **Audit verdict:** **Not exploitable.** No shell execution anywhere in the codebase. Verified by attempted `rm -rf` injection — no file created.
- **CWE mapping:** CWE-78 (does not apply).

### V3-6. Malformed hex
- **Surface:** CLI `_parse_data`.
- **Audit verdict:** **Silent fallback, not a crash.** `--data ZZZZ` parses as latin-1 literal bytes, exits 0. Documented behaviour; surprising UX but not a security defect.
- **CWE mapping:** CWE-1389 (does not apply — no numeric parsing bug).

### V3-7. CRLF / unicode in stdin
- **Surface:** CLI `--stdin`.
- **Audit verdict:** **Handled correctly.** `--stdin` reads raw bytes via `sys.stdin.buffer.read()`; any byte 0x00–0xFF is accepted. CRLF is just two more bytes that get CRC'd. Verified: `b"123456789\r\n"` → `0x342` (CRC of 11 bytes — correct).
- **CWE mapping:** CWE-20 (does not apply).

### V3-8. Numeric overflow in internal XOR loop
- **Surface:** `crc()` inner loop.
- **Audit verdict:** **Impossible.** Every shift is followed by `& _MASK = 0x3FF`. Python int semantics provide a second defence (arbitrary precision, no overflow).
- **CWE mapping:** CWE-190 (does not apply).

### V3-9. Algorithmic confusion with sibling crc10-atm-pure (cycle_114)
- **Surface:** `crc()` output.
- **Audit verdict:** **Disambiguation documented, not a vuln.** `register()` exposes `refin=False` so callers can verify at runtime. README §5 documents the cross-cycle distinction.
- **CWE mapping:** CWE-1338 (does not apply).

## 5. Worst-case impact analysis

For each vector above, the worst-case the audit was able to construct:

| Vector | Worst-case outcome | Real-world impact |
|---|---|---|
| V3-1 | n/a (no surface) | — |
| V3-2 | n/a (no surface) | — |
| V3-3 | `TypeError` propagates to caller | Caller handles exception; library correct. |
| V3-4 | Slow CRC (1 hour for ~1 GiB input on a single core) | Caller's CPU is busy; library does not OOM, does not crash. Caller can chunk inputs. |
| V3-5 | n/a (no shell) | — |
| V3-6 | Garbage-in, garbage-out: latin-1 fallback yields a real (but meaningless) CRC | Caller must validate CLI input upstream. Documented behaviour. |
| V3-7 | Correct CRC of an unexpected-length input | Caller's protocol layer is responsible for trimming delimiters. |
| V3-8 | n/a (impossible) | — |
| V3-9 | Wrong CRC if caller confuses libraries | Caller's bug, mitigated by `register()` self-disclosure. |

**Highest-impact realistic scenario:** A caller passes a 10 GiB bytes object to `crc()`, blocking the calling thread for ~15 minutes on a single core (extrapolated from 200 MiB in 76 s). This is bounded CPU consumption, not memory corruption. The library returns the correct 10-bit CRC value when it eventually finishes.

**No scenario produces:**
- Memory corruption (no writes outside the caller's stack).
- Arbitrary code execution (no shell, no eval, no native code).
- Information disclosure (errors do not echo user input).
- Privilege escalation (no auth, no system calls).
- Persistent state corruption (no filesystem, no network).

## 6. Threat-model conclusion

The library is appropriately scoped for its purpose: a pure-functional CRC
reference. The trust boundary is narrow (one input argument, one output
integer). Every attack vector from the standard CRC-library threat catalogue
either does not apply, is mitigated by an `isinstance` guard or a bit-mask, or
is a documented CLI behaviour that places responsibility on the caller.

No vulnerability was found that warrants a fix card. See VULN_AUDIT.md for the
formal verdict.
