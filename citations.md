# Citations — Stateful Hash-Based Signature Deployment Assessment

Primary sources first. Every measured or spec-derived claim in this
pack cites one of the bundled standards or a named implementation
document; tool-support claims cite the tool's own documentation or
source. Bundled copies live under `src/` and their SHA-256 digests are
verified by `scripts/run_all.sh` before any benchmark runs.

## Standards (bundled)

- **RFC 8391 — XMSS: eXtended Merkle Signature Scheme**
  (A. Hülsing, D. Butin, S. Gazdag, J. Rijneveld, A. Mohaisen,
  May 2018). Defines the XMSS signature scheme: WOTS+ one-time
  signatures, Merkle-tree authentication paths, key and signature
  formats, parameter sets XMSS-SHA2_10_256 / _16_256 / _20_256 and
  XMSS-SHAKE_10_256 / _16_256 / _20_256, and the signature size
  formula used in C-02/C-05. Bundled as `src/RFC.8391.txt`
  (SHA-256 `1c9af7d63cd9ba38f6be8c72bb91f56d83fcce8e158c6da89782df727130106e`).
  https://www.rfc-editor.org/rfc/rfc8391.txt

- **RFC 8554 — Leighton-Micali Signatures (LMS)**
  (D. McGrew, M. Curcio, S. Fluhrer, April 2019). Defines LMS and
  HSS: LM-OTS one-time signatures, LMS Merkle trees, HSS multi-tree
  signatures, key and signature formats, parameter sets
  LMS_SHA256_H5/H10/H15/H20 with LMOTS_SHA256_W1/W2/W4/W8, and the
  signature size formula used in C-01/C-04. §6.2 states a one-time
  key must never be reused — the invariant violated by F-01. Bundled
  as `src/RFC.8554.txt`
  (SHA-256 `d5bfdbd457dfe7bc5f67cc1f62482999c2f55bf8033f2af56da323f2ffc2c055`).
  https://www.rfc-editor.org/rfc/rfc8554.txt

- **NIST SP 800-208 — Recommendation for Stateful Hash-Based
  Signature Schemes** (D. Cooper et al., October 2020). Recommends
  LMS and XMSS for use in US federal systems, requires that the
  private-key state be managed so that no one-time key is ever
  reused, and describes state-management requirements including
  backup and recovery. The state-rollback failure mode (F-01) is a
  violation of the state-management requirements in SP 800-208.
  Bundled as `src/SP.800-208.pdf`
  (SHA-256 `9ac6bee3da878e883874847b40f80d2265d6268385d8201f866581437533465f`).
  https://doi.org/10.6028/NIST.SP.800-208

- **FIPS 205 — Stateless Hash-Based Digital Signature Standard**
  (SLH-DSA, August 2024). Defines SLH-DSA parameter sets and Table 2
  key/signature sizes used in C-03. Bundled as `src/FIPS.205.pdf`
  (SHA-256 `8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d`).
  https://doi.org/10.6028/NIST.FIPS.205

- **FIPS 203 / FIPS 204** (ML-KEM / ML-DSA, August 2024). Bundled as
  `src/FIPS.203.pdf` and `src/FIPS.204.pdf`; referenced only for the
  OpenSSL algorithm-listing check in C-20 (OpenSSL 3.0.13 on this
  machine lists none of ML-DSA, SLH-DSA, LMS or XMSS).
  https://doi.org/10.6028/NIST.FIPS.203 and
  https://doi.org/10.6028/NIST.FIPS.204

- **RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)**
  (January 2017). Source of the 64-byte Ed25519 signature baseline
  used in C-19. Not bundled; the 64-byte value is the standard
  signature length for Ed25519.
  https://www.rfc-editor.org/rfc/rfc8032.txt

## Implementations

- **liboqs 0.16.0** (Open Quantum Safe project). C library providing
  LMS, XMSS (stateful, `OQS_SIG_STFL` API) and SLH-DSA. The stateful
  keygen/sign support used here is experimental and gated behind
  `OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN` and
  `OQS_ALLOW_STFL_KEY_AND_SIG_GEN`. The secure-store callback
  behaviour in C-17 is in the bundled source
  `src/liboqs-0.16.0/src/sig_stfl/lms/sig_stfl_lms_functions.c`
  (refusal without a store callback) and
  `src/liboqs-0.16.0/src/sig_stfl/lms/sig_stfl_lms.c`
  (`OQS_SECRET_KEY_LMS_set_store_cb` requires a non-NULL context).
  Bundled as `src/liboqs-0.16.0.tar.gz`
  (SHA-256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`).
  https://github.com/open-quantum-safe/liboqs

- **hash-sigs** (Cisco). C reference implementation of HSS/LMS
  (RFC 8554), used as the second LMS implementation for
  cross-implementation checks (C-15). Bundled as
  `src/hash-sigs.tar.gz` (commit `7768828`,
  SHA-256 `920f8b3de2d317445315b1714e7f09c328f4c9e0645aa2c6dff83f4040f9ebaa`).
  https://github.com/cisco/hash-sigs

- **xmss-reference** (J. Rijneveld et al.). C reference
  implementation of XMSS (RFC 8391), used as the second XMSS
  implementation for cross-implementation checks (C-15). Bundled as
  `src/xmss-reference.tar.gz` (commit `171ccbd`,
  SHA-256 `92d74dcbced70fe9371205782ac9df42e59802cd321074bfb5f98d03664a8023`).
  https://github.com/joostrijneveld/xmss-reference

- **slh-dsa 0.2.5** (Python, pure). Pure-Python SLH-DSA
  implementation used as the second SLH-DSA implementation (C-03,
  C-06, C-23). Bundled as `src/slh_dsa-0.2.5-py3-none-any.whl`
  (SHA-256 `9d8292a4b606085089fedbe526d26c8036e9a57da43b67ac3e97f44545e6bd9d`).
  https://pypi.org/project/slh-dsa/

## Tools

- **OpenSSL** (system library, `openssl version` reported in
  `outputs/run1/results.json`). The algorithm-listing check in C-20
  uses `openssl list -public-key-algorithms` (ML-DSA and SLH-DSA
  listed; LMS and XMSS not listed on this machine).
  https://www.openssl.org/
