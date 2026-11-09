# Stateful Hash-Based Signature Deployment Assessment

Reproducible LMS / XMSS / SLH-DSA assessment across pinned liboqs
0.16.0 (C), the hash-sigs LMS reference (C), the xmss-reference XMSS
reference (C) and slh-dsa 0.2.5 (pure Python), with adversarial-input
behaviour, state-exhaustion behaviour, one reproduced
state-management failure mode and a tested remediation.

## What this pack contains

- `src/benchmark.py` — the benchmark + adversarial harness. Sizes
  (RFC 8554 / RFC 8391 formulas, FIPS 205 Table 2), state sizes and
  signature budgets, throughput (keygen/sign/verify medians, peak
  RSS), adversarial cases, cross-implementation checks, determinism,
  state exhaustion, artifact-size impact, environment.
- `src/stfl_driver.c` — liboqs stateful LMS/XMSS driver (info/keygen/
  sign/sign-many/verify/remaining/bench). Built with
  `-DOQS_ALLOW_STFL_KEY_AND_SIG_GEN`.
- `src/pq_driver.c` — liboqs SLH-DSA driver.
- `src/ref_lms.c` — hash-sigs LMS driver; `src/ref_xmss.c` —
  xmss-reference XMSS driver.
- `remediation/` — the reproduced failure mode (F-01), the journaled
  remediation, and the regression test (12 checks, all passing).
- `fixtures/test-vectors.json` — RFC size tables and the test message.
- `outputs/run1/` — run logs + `results.json`. The run1 harness died
  silently during the determinism section, so `results.json` is
  reconstructed: sections 0–6 rebuilt verbatim from the unedited
  `outputs/run1-build.log`, the missing determinism checks and
  sections 7–9 measured fresh on the same machine and code (see
  PACK-READY.md). `outputs/run2-clean/` was not produced
  (clean reproduction not run — see Limitations).
- `docs/index.html` — rendered findings page (tables generated from
  `outputs/run1/results.json`).
- `claims.md` — claim-to-evidence index (C-01…C-24; C-21 is marked
  NOT RUN — the clean reproduction was not performed).
- `findings.md` — severity-ranked findings (F-01 High; F-02, F-03,
  F-04, F-07, F-09 Medium; F-05, F-06, F-08 Low).
- `citations.md` — primary sources for every spec-derived claim.
- `evidence.json` — machine-readable summary of the run.

## How to run

```bash
bash scripts/run_all.sh            # full rebuild + benchmark into outputs/run1/
bash scripts/clean_reproduce.sh    # fresh-copy re-run into outputs/run2-clean/ + comparison
bash scripts/verify_digests.sh     # SHA-256 check over all shippable files
```

Requirements: gcc, cmake, make, python3 (>= 3.10), OpenSSL dev
headers (`libssl-dev`) for `-lcrypto`, ~500 MB free disk for the
liboqs build. No network access is needed: all sources are bundled
under `src/` and their SHA-256 digests are verified before any
benchmark runs.

The full run takes on the order of 1.5–2 hours on this machine:
key generation dominates (LMS H15/W4 ~8.5 s, XMSS H16 ~73 s per
keygen; H20 keygen exceeds 240 s and is therefore sizes-only).

## Results (run1)

Sizes match the RFC formulas and FIPS 205 Table 2 exactly for every
parameter set (see `outputs/run1/results.json`, `sizes_verified`):

| Scheme | pk bytes | sig bytes |
|--------|----------|-----------|
| LMS_SHA256_H5_W4 | 60 | 2352 |
| LMS_SHA256_H10_W4 | 60 | 2512 |
| LMS_SHA256_H10_W1 | 60 | 8848 |
| LMS_SHA256_H15_W4 | 60 | 2672 |
| XMSS-SHA2_10_256 | 68 | 2500 |
| XMSS-SHA2_16_256 | 68 | 2692 |
| SLH-DSA-SHA2-128s | 32 | 7856 |
| SLH-DSA-SHA2-128f | 32 | 17088 |
| SLH-DSA-SHA2-256s | 64 | 29792 |
| SLH-DSA-SHA2-256f | 64 | 49856 |

Keygen cost grows exponentially with tree height: LMS liboqs H10/W4
244 ms, H15/W4 8,113 ms, H20/W4 >240 s; XMSS liboqs SHA2 H10 1,163 ms,
H16 73,719 ms (exact run1 medians in `outputs/run1/results.json`,
`throughput`). Sign and verify are milliseconds for liboqs XMSS and
for the hash-sigs LMS reference — but liboqs LMS sign takes 9,448 ms
at H15 (vs 0.91 ms for hash-sigs) and xmss-reference XMSS sign takes
159,049 ms at H16 (vs 1.84 ms for liboqs): the signing cost depends
on the implementation and grows with the tree in the slow direction
(see F-09). The pure-Python slh-dsa signer takes seconds per
signature (n=1, indicative only).

State: LMS budget is 2^H − 1 signatures (1023 for H10), XMSS usable
budget is also 2^H − 1 (1023 for H10 — the tree has 2^H leaves but
liboqs/xmss-reference report 2^H − 1 as the usable total). Exhaustion
is not fail-closed (F-07): the LMS 32nd signature past the reported
total verifies VALID, and the XMSS 1024th is produced but verifies
INVALID. The liboqs serialized LMS secret key for H10/W4 is
10,980 bytes vs 64 bytes for hash-sigs; XMSS-SHA2_10_256 is 1,377
bytes (liboqs) vs 136 bytes (xmss-reference).

Cross-implementation agreement: liboqs↔hash-sigs LMS and
liboqs↔xmss-reference XMSS signatures verify in both directions.
Signing the same message from the same state produces byte-identical
signatures; the updated state advances the leaf index by exactly one.

## The failure mode (F-01, High)

Stateful private-key state not persisted atomically after signing:
a crash or backup restore between releasing a signature and
persisting the updated state reuses the same one-time signature
index, and both signatures verify. Reproduce:

```bash
python3 remediation/reproduce_weakness.py   # prints REPRODUCED
```

Remediation: `remediation/state_journal.py` commits the updated
state before releasing the signature (temp file + fsync + rename +
directory fsync, plus a monotonic journal that refuses stale state
with `STATE_ROLLBACK`). Regression test:

```bash
python3 remediation/test_remediation.py --driver src/stfl_driver
# regression test: 12 passed, 0 failed
```

## Comparison rule

`src/compare_runs.py` compares only deterministic fields between
`outputs/run1/` and `outputs/run2-clean/`: size-match flags, state
fields, exhaustion outcomes, adversarial outcomes,
cross-implementation booleans, determinism booleans and leaf
indices, and remediation verdicts. Timing medians and peak-RSS
values are reported in both runs but are NOT asserted equal — they
vary between runs by design. Digests of freshly generated
keys/signatures are not compared (keys are fresh per run).

## Limitations (honest gaps)

- `outputs/run1/results.json` is reconstructed, not a single unedited
  benchmark run (see `outputs/run1/` above and PACK-READY.md).
- No clean-environment reproduction (`outputs/run2-clean/`) was
  produced: `scripts/clean_reproduce.sh` takes ~2–3 hours and was
  not run, so claim C-21 (clean reproduction matches run1) is
  unproven.
- H20 parameter sets (LMS_SHA256_H20_W4, XMSS-SHA2_20_256,
  XMSS-SHAKE_20_256) are sizes-only: keygen exceeds 240 s on this
  machine, so no keygen-dependent measurement was attempted. Their
  state entries record `not_measured` with the reason.
- Rust and Go implementations were not benchmarked: this machine has
  no cargo/rustc or Go toolchain.
- slh-dsa throughput is n=1 and indicative only.
- The liboqs stateful keygen/sign API used here is experimental and
  gated behind
  `OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN`.

## Digests

`SHA256SUMS` covers every shippable file. Excluded: `docs/index.html`
(generated page; its own digest row would be self-referential),
`submission-text-final.txt` (submission draft), the liboqs
source/build trees, the extracted reference-implementation trees and
the compiled drivers (build artefacts, rebuilt by `run_all.sh`),
the venv, `.git`, and `SHA256SUMS` itself. Verify with:

```bash
bash scripts/verify_digests.sh
```
