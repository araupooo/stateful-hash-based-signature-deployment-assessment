# Findings — Stateful Hash-Based Signature Deployment Assessment

Severity-ranked findings from the benchmark and adversarial runs
(`outputs/run1/`). Every finding is an actually
observed behaviour, with the trigger command and the evidence location
named. Sizes, state sizes, exhaustion and cross-implementation results
are deterministic; timing medians vary
between runs by design and are reported exactly in
`outputs/run1/results.json` and in the tables in `docs/index.html`.
The timing values quoted below are the run1 medians from
`outputs/run1/results.json`.

## F-01 — High: stateful private-key state not persisted atomically after signing, so a crash or backup restore reuses the same one-time signature index

A stateful LMS/XMSS private key advances its leaf index on every
signature. The reference caller in this pack
(`remediation/vulnerable_signer.py`) releases the signature first and
persists the updated state afterwards. If the process crashes, is
killed, or the operator restores an older state file between those two
steps, the next signature reuses the leaf index of the already-released
signature. Reusing a one-time signature (OTS) key with two different
messages leaks the private OTS key material: each LM-OTS signature
reveals the private value for every chunk it covers, and two
signatures under the same OTS key reveal the private values for
nearly all chunk positions, letting an observer forge signatures under
that leaf. RFC 8554 §6.2 and SP 800-208 both state that a one-time key
must never be reused; a state rollback is a silent violation of that
rule because both signatures still verify.

Reproduction (LMS_SHA256_H5_W4, liboqs 0.16.0):

```
python3 remediation/reproduce_weakness.py
```

Output (`outputs/run1/remediation-before.log`):

```
sign A: index=0 (released, then CRASH before persist)
sign B: index=0 (signed from the stale state file)
same leaf index used twice: True
verify signature A: verify VALID
verify signature B: verify VALID
REPRODUCED
```

The same failure was reproduced in the regression harness before the
remediation was applied (`remediation/test_remediation.py`, BEFORE
section: first signature valid, reused-index signatures both verify,
same index used twice — index A=0, index B=0).

Remediation: `remediation/state_journal.py` (`JournaledSigner`) commits
the updated state before the signature is released — write the new
state to a temporary file, fsync it, rename it over the state file,
fsync the directory, then update a monotonic journal
(`journal.json`: `key_id`, `last_committed_index`, `released`) the
same way — and refuses to sign from any state whose next index is at
or below `last_committed_index` (`STATE_ROLLBACK`). A crash before the
commit releases nothing and the state is reusable at the same index
exactly once. The regression test
(`remediation/test_remediation.py`, 12 checks: 3 BEFORE + 9 AFTER)
passes with exit 0; see `outputs/run1/remediation-after.log`. The
patch that converts the vulnerable caller to the journaled caller is
`remediation/remediation.patch` (applies cleanly with `patch -p1`).

Severity: High — a single crash or restore silently breaks the
one-time-use invariant the whole scheme depends on, and both
signatures verify, so nothing in the verification path detects it.

## F-02 — Medium: liboqs serialized LMS state is ~170x the reference implementation's (10,980 B vs 64 B for LMS_SHA256_H10_W4)

The liboqs serialized secret key for LMS_SHA256_H10_W4 is 10,980
bytes; the hash-sigs reference serialized key for the same parameter
set is 64 bytes (8 bytes of index + 8 bytes of flags + 32 bytes of
seed + 16 bytes of state, per `HSS_MAX_PRIVATE_KEY_LEN`). The liboqs
form carries the auxiliary Merkle-tree data needed to resume signing
without recomputing the tree, while the reference recomputes from the
seed. The consequence is operational: any backup, replication or
transport of the private key must move ~11 KB per LMS key (and more
for larger H) instead of 64 bytes, and a state store that truncates or
corrupts the trailing bytes silently destroys the key. XMSS shows the
same pattern at a smaller scale: liboqs serialized secret key for
XMSS-SHA2_10_256 is 1,377 bytes vs 136 bytes for xmss-reference.

Evidence: `outputs/run1/results.json` (`state` section);
`outputs/run1/benchmark-run.log` (STATE lines).

## F-03 — Medium: key generation cost grows exponentially with tree height; H20 keygen exceeds 240 s on this machine

Measured keygen (run1 medians, in-process; exact values in
`outputs/run1/results.json`):

- LMS (liboqs): H5/W4 7.8 ms, H10/W4 244 ms, H15/W4 8,113 ms.
  hash-sigs is roughly 2x faster at keygen (H15/W4 3,978 ms).
- XMSS (liboqs): SHA2 H10 1,163 ms, SHA2 H16 73,719 ms;
  SHAKE H10 2,674 ms, SHAKE H16 171,054 ms. xmss-reference is
  roughly 2x slower at keygen (SHA2 H16 159,061 ms).
- LMS_SHA256_H20_W4: killed by `timeout 240` with no output
  (>240 s).

A 2^20-leaf tree is therefore not generatable on demand on this class
of machine; it must be generated once, offline, and its state stored
and protected for the lifetime of the key (which makes F-01 worse:
the state file is long-lived and will be backed up and restored many
times). H20 parameter sets in this pack are sizes-only for exactly
this reason: no keygen-dependent measurement was attempted for them,
and the state entries record `not_measured` with the >240 s reason
instead of an invented number.

Evidence: `outputs/run1/results.json` (`throughput` section);
`outputs/run1/benchmark-run.log`.

## F-04 — Medium: liboqs LMS/XMSS key and signature encodings carry a 4-byte framing prefix the bare RFC formats do not, so raw values are not interchangeable across implementations

- LMS: liboqs (and hash-sigs) public keys are 60 bytes and signatures
  are 4 bytes longer than the bare RFC 8554 values (pk 56, sig 2508
  for H10/W4). The extra 4 bytes are the HSS levels-count prefix.
- XMSS: liboqs public keys are 68 bytes vs 64 bytes bare RFC 8391
  (the 4-byte OID prefix); signatures are exactly the RFC size
  (2500 bytes for XMSS-SHA2_10_256) because the signature carries no
  OID.

Verified: liboqs↔hash-sigs LMS and liboqs↔xmss-reference XMSS
signatures verify in both directions **only after the framing is
accounted for** — the drivers strip/add the prefix explicitly
(`src/stfl_driver.c`, `src/ref_lms.c`, `src/ref_xmss.c`). A caller
that feeds a bare RFC 8554 public key (56 bytes) to liboqs, or a
liboqs public key (60 bytes) to a bare-RFC verifier, gets a
length/parse failure, not a wrong verification. The hazard is a
deployment that stores or transmits the prefixed form and later
verifies with a bare-RFC implementation, or vice versa.

Evidence: `outputs/run1/results.json` (`sizes_verified`,
`cross_implementation`); `outputs/run1/benchmark-run.log`
(XIMPL lines).

## F-05 — Low: liboqs stateful signing fails closed without a secure-store callback, but a NULL callback context is silently ignored

liboqs LMS/XMSS `sign` refuses to produce a signature when no
secure-store callback is set (`sig_stfl_lms_functions.c`: "No
Secure-store set for secret key"; the signature buffer is wiped if
the store fails). That is fail-closed and correct. But
`OQS_SECRET_KEY_LMS_set_store_cb` silently ignores a NULL context
(`if (sk && store_cb && context)`), so a caller that passes a NULL
context believing it registered a store callback gets no error at
registration time and only discovers the problem when signing fails.
The driver in this pack passes a non-NULL static context and asserts
the stored key matches a re-serialization (`src/stfl_driver.c`).

Evidence: `src/liboqs-0.16.0/src/sig_stfl/lms/sig_stfl_lms_functions.c`
and `src/sig_stfl/lms/sig_stfl_lms.c` (bundled source, not a tracked
file); driver behaviour in `outputs/run1/benchmark-run.log`.

## F-06 — Low: the pure-Python SLH-DSA signer takes seconds per signature; the stateless alternative is only fast in C

slh-dsa 0.2.5 (pure Python) signing is measured at n=1 and is
indicative only — it takes seconds per signature, versus
sub-millisecond verify/sign for liboqs SLH-DSA in C (exact medians in
`outputs/run1/results.json`). SLH-DSA has no state to manage, so it
sidesteps F-01 entirely, but a deployment that picks the pure-Python
implementation for its simplicity pays for it in latency. Key and
signature sizes match FIPS 205 Table 2 exactly in both
implementations (pk 32/48/64, sk 64/96/128, sig 7856–49856 bytes).

Evidence: `outputs/run1/results.json` (`throughput`,
`sizes_verified`); `outputs/run1/benchmark-run.log`.

## F-07 — Medium: state exhaustion is not fail-closed — liboqs permits one signature past the reported budget, and the two schemes fail differently

liboqs reports the signature budget as 2^H − 1 (31 for LMS H5,
1023 for XMSS H10) and `remaining` reaches 0 after that many
signatures. But the tree actually has 2^H leaves, and the signing
path performs no exhaustion check of its own — it signs while the
leaf index is in range. Measured behaviour (`outputs/run1/results.json`,
`exhaustion`; `outputs/run1/benchmark-run.log`, EXHAUST lines):

- LMS (LMS_SHA256_H5_W4): signing all 31 signatures succeeds; the
  32nd signature (leaf index 31) is produced with rc 0 and **verifies
  VALID** under the public key. Only the 33rd attempt stops the key:
  the serialized state after the 32nd signature fails to deserialize
  ("ERROR deserialize secret key failed"), so the key is dead — but
  only after one extra valid signature has already been emitted.
- XMSS (XMSS-SHA2_10_256): signing all 1023 signatures succeeds; the
  1024th signature (leaf index 1023) is produced with rc 0 but
  **verifies INVALID**. A caller that signs past the budget gets a
  signature that no verifier will accept, with no error from the
  signer.

The reported budget is therefore wrong by one for LMS (the true
usable budget is 2^H, not 2^H − 1), and for XMSS the signer silently
emits an invalid signature instead of refusing. A deployment that
enforces key rotation at `remaining == 0` is safe in the LMS case
(it rotates one signature early) but must not treat "sign returned
success" as "signature is valid" in the XMSS case — verification is
the only check that catches it.

Evidence: `outputs/run1/results.json` (`exhaustion`);
`outputs/run1/benchmark-run.log` (EXHAUST lines); liboqs source
`src/liboqs-0.16.0/src/sig_stfl/lms/sig_stfl_lms_functions.c`
(`OQS_SIG_STFL_alg_lms_sign` performs no budget check before
calling the underlying sign) and
`src/liboqs-0.16.0/src/sig_stfl/xmss/external/xmss.c`
(`xmss_total_signatures`: `*max = ((1ULL << params.full_height) - 1)`).

## F-08 — Low: cross-implementation agreement verified in both directions for LMS and XMSS

- LMS: liboqs→hash-sigs VALID and hash-sigs→liboqs VALID for
  LMS_SHA256_H5_W4, H10/W4, H10/W1 (and the other measured sets).
- XMSS: liboqs→xmss-reference VALID and xmss-reference→liboqs VALID
  for XMSS-SHA2_10_256 and XMSS-SHAKE_10_256.
- Determinism: signing the same message from the same state produces
  byte-identical signatures in liboqs LMS/XMSS and in the reference
  implementations; signing the same message from the updated state
  advances the leaf index by exactly one and produces a different
  signature.

This is a positive result: the RFC-derived size formulas, the framing
prefixes in F-04, and the leaf-index layout (LMS `q` at signature
offset 4, after the 4-byte HSS prefix; XMSS `idx` at offset 0) are all
confirmed by interoperating implementations rather than assumed.

Evidence: `outputs/run1/results.json` (`cross_implementation`,
`determinism`); `outputs/run1/benchmark-run.log` (XIMPL, DET lines).

## F-09 — Medium: signing cost is implementation-dependent and grows with tree height in the slow direction — liboqs LMS sign takes ~9.4 s at H15 while hash-sigs takes 0.9 ms; xmss-reference XMSS sign takes ~159 s at H16 while liboqs takes 1.8 ms

The two implementations have opposite performance profiles, because
one side caches the Merkle-tree traversal state and the other
recomputes the authentication path from the seed on every signature
(run1 medians in `outputs/run1/results.json`, `throughput`):

- LMS sign: liboqs H5/W4 10.5 ms, H10/W4 272 ms, H15/W4 9,448 ms
  (roughly ×35 per +5 heights — the cost grows with 2^H);
  hash-sigs H5/W4 0.30 ms, H10/W4 0.54 ms, H15/W4 0.91 ms
  (flat — ~10,000x faster than liboqs at H15).
- XMSS sign: liboqs SHA2 H10 2.0 ms, H16 1.8 ms (flat — the BDS
  traversal state is kept); xmss-reference SHA2 H10 2,505 ms,
  H16 159,049 ms (~159 s — the auth path is recomputed per sign).
- Verify stays fast everywhere (LMS ≤ 0.9 ms, XMSS ≤ 1.9 ms).

The consequence is a deployment trap: the same parameter set can be
either fast or unusable depending on which implementation signs, and
the slow direction scales with the tree size, so a key that signs
fine at H10 can take seconds (LMS/liboqs) or minutes (XMSS/reference)
per signature at H16. Key generation shows the same 2x gap in the
other direction (liboqs LMS keygen is ~2x slower than hash-sigs;
xmss-reference keygen is ~2x slower than liboqs), so no single
implementation is fastest at everything.

Evidence: `outputs/run1/results.json` (`throughput`);
`outputs/run1/benchmark-run.log` (TIMING lines).

## Not measured (honest gaps)

- `outputs/run1/results.json` is reconstructed, not a single unedited
  benchmark run: the run1 harness died silently during the
  determinism section (after the XMSS-SHAKE_16_256 liboqs check),
  before the exhaustion, artifact-size and environment sections.
  Sections 0–6 were rebuilt verbatim from the unedited
  `outputs/run1-build.log`; the missing determinism checks
  (XMSS-SHAKE_16_256 xmss-reference, all 12 SLH-DSA sets) and
  sections 7–9 were measured fresh on the same machine and code and
  appended. See PACK-READY.md for the reconstruction method.
- No clean-environment reproduction (`outputs/run2-clean/`) was
  produced: `scripts/clean_reproduce.sh` takes ~2–3 hours
  (liboqs rebuild + full benchmark) and was not run. Claim C-21
  (clean reproduction matches run1) is therefore unproven, not
  verified.
- H20 parameter sets (LMS_SHA256_H20_W4, XMSS-SHA2_20_256,
  XMSS-SHAKE_20_256): sizes only. Keygen exceeds 240 s on this
  machine, so no keygen-dependent measurement was attempted.
- Rust and Go implementations: not run — this machine has no
  cargo/rustc or Go toolchain.
- slh-dsa throughput is n=1 and indicative only.
- No network-dependent check was performed; all sources are bundled
  under `src/` and verified by SHA-256 in `scripts/run_all.sh`.
