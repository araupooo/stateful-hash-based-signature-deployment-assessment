#!/usr/bin/env bash
# Reproduce the stateful hash-based signature deployment assessment
# pack end to end.
#
#   bash scripts/run_all.sh [run-name]      # default run-name: run1
#
# What it does:
#   1. Verifies the SHA-256 of every bundled source (liboqs tarball,
#      hash-sigs + xmss-reference tarballs, slh-dsa wheel, FIPS
#      203/204/205 PDFs, RFC 8391/8554 texts, SP 800-208 PDF).
#   2. Builds liboqs 0.16.0 from the bundled tarball (ML-DSA +
#      SLH-DSA + stateful LMS/XMSS, Release, stateful keygen/sign
#      enabled) unless already built.
#   3. Compiles the drivers: src/pq_driver.c (SLH-DSA), src/stfl_driver.c
#      (LMS/XMSS stateful), src/ref_lms.c (hash-sigs), src/ref_xmss.c
#      (xmss-reference).
#   4. Creates a Python venv and installs slh-dsa 0.2.5 from the
#      bundled wheel (no network needed).
#   5. Runs the benchmark + adversarial harness (src/benchmark.py) into
#      outputs/<run-name>/, producing benchmark-run.log (unedited) and
#      results.json.
#   6. Runs the remediation reproduction + regression test into the same
#      output directory (remediation-before.log, remediation-after.log).
#   7. Regenerates docs/index.html from the run results and evidence.json
#      from the run results + remediation logs.
#   8. Regenerates SHA256SUMS over the shippable files.
#
# Requirements: gcc, cmake, make, python3 (>= 3.10), OpenSSL dev headers
# (libssl-dev) for -lcrypto, ~500 MB free disk for the liboqs build.
# No network access is needed: all sources are bundled under src/.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="${1:-run1}"
OUT="outputs/$RUN"
mkdir -p outputs
LIBOQS_TARBALL="src/liboqs-0.16.0.tar.gz"
LIBOQS_SHA256="162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae"
HASHSIGS_TARBALL="src/hash-sigs.tar.gz"
HASHSIGS_SHA256="920f8b3de2d317445315b1714e7f09c328f4c9e0645aa2c6dff83f4040f9ebaa"
XMSSREF_TARBALL="src/xmss-reference.tar.gz"
XMSSREF_SHA256="92d74dcbced70fe9371205782ac9df42e59802cd321074bfb5f98d03664a8023"
SLHDSA_WHEEL="src/slh_dsa-0.2.5-py3-none-any.whl"
SLHDSA_SHA256="9d8292a4b606085089fedbe526d26c8036e9a57da43b67ac3e97f44545e6bd9d"
FIPS203="src/FIPS.203.pdf"
FIPS203_SHA256="fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac"
FIPS204="src/FIPS.204.pdf"
FIPS204_SHA256="57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b"
FIPS205="src/FIPS.205.pdf"
FIPS205_SHA256="8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d"
RFC8391="src/RFC.8391.txt"
RFC8391_SHA256="1c9af7d63cd9ba38f6be8c72bb91f56d83fcce8e158c6da89782df727130106e"
RFC8554="src/RFC.8554.txt"
RFC8554_SHA256="d5bfdbd457dfe7bc5f67cc1f62482999c2f55bf8033f2af56da323f2ffc2c055"
SP800208="src/SP.800-208.pdf"
SP800208_SHA256="9ac6bee3da878e883874847b40f80d2265d6268385d8201f866581437533465f"

echo "=== stateful hash-based signature deployment assessment pack: $RUN ==="
echo "date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 1. verify bundled sources ---
echo "$LIBOQS_SHA256  $LIBOQS_TARBALL" | sha256sum -c -
echo "$HASHSIGS_SHA256  $HASHSIGS_TARBALL" | sha256sum -c -
echo "$XMSSREF_SHA256  $XMSSREF_TARBALL" | sha256sum -c -
echo "$SLHDSA_SHA256  $SLHDSA_WHEEL" | sha256sum -c -
echo "$FIPS203_SHA256  $FIPS203" | sha256sum -c -
echo "$FIPS204_SHA256  $FIPS204" | sha256sum -c -
echo "$FIPS205_SHA256  $FIPS205" | sha256sum -c -
echo "$RFC8391_SHA256  $RFC8391" | sha256sum -c -
echo "$RFC8554_SHA256  $RFC8554" | sha256sum -c -
echo "$SP800208_SHA256  $SP800208" | sha256sum -c -

# --- 2. liboqs (ML-DSA + SLH-DSA + stateful LMS/XMSS) ---
if [ ! -d src/liboqs-0.16.0 ]; then
  echo "extracting liboqs 0.16.0 ..."
  tar xzf "$LIBOQS_TARBALL" -C src
fi
if [ ! -f src/liboqs-build/lib/liboqs.a ]; then
  echo "configuring liboqs (ML-DSA + SLH-DSA + stateful LMS/XMSS) ..."
  mkdir -p src/liboqs-build
  (cd src/liboqs-build && cmake ../liboqs-0.16.0 -DCMAKE_BUILD_TYPE=Release \
    -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF \
    -DOQS_ENABLE_KEM_BIKE=OFF -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
    -DOQS_ENABLE_KEM_FRODOKEM=OFF -DOQS_ENABLE_KEM_HQC=OFF \
    -DOQS_ENABLE_KEM_KYBER=OFF -DOQS_ENABLE_KEM_ML_KEM=OFF \
    -DOQS_ENABLE_KEM_NTRU=OFF -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
    -DOQS_ENABLE_SIG_CROSS=OFF -DOQS_ENABLE_SIG_FALCON=OFF \
    -DOQS_ENABLE_SIG_MAYO=OFF -DOQS_ENABLE_SIG_MQOM=OFF \
    -DOQS_ENABLE_SIG_SNOVA=OFF -DOQS_ENABLE_SIG_UOV=OFF \
    -DOQS_ENABLE_SIG_STFL_LMS=ON -DOQS_ENABLE_SIG_STFL_XMSS=ON \
    -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
    > ../../outputs/build-liboqs-cmake.log 2>&1)
  echo "building liboqs ..."
  (cd src/liboqs-build && make -j"$(nproc)" > ../../outputs/build-liboqs-make.log 2>&1)
fi
# Scrub the absolute build path out of the build logs (cmake records it);
# the logs must not leak the local workspace path into the shipped pack.
sed -i "s|$PWD|.|g" outputs/build-liboqs-cmake.log outputs/build-liboqs-make.log 2>/dev/null || true
ls -la src/liboqs-build/lib/liboqs.a

# --- 2b. reference implementations (extract from bundled tarballs) ---
if [ ! -d src/hash-sigs ]; then
  echo "extracting hash-sigs ..."
  tar xzf "$HASHSIGS_TARBALL" -C src
fi
if [ ! -d src/xmss-reference ]; then
  echo "extracting xmss-reference ..."
  tar xzf "$XMSSREF_TARBALL" -C src
fi

# --- 3. drivers ---
echo "compiling liboqs drivers ..."
gcc -O2 -Wall -I src/liboqs-build/include -o src/pq_driver \
  src/pq_driver.c src/liboqs-build/lib/liboqs.a -lcrypto
gcc -O2 -Wall -DOQS_ALLOW_STFL_KEY_AND_SIG_GEN -I src/liboqs-build/include -o src/stfl_driver \
  src/stfl_driver.c src/liboqs-build/lib/liboqs.a -lcrypto
echo "compiling reference drivers ..."
gcc -O2 -Wall -Wno-deprecated-declarations -I src/hash-sigs -o src/ref_lms src/ref_lms.c \
  src/hash-sigs/hss.c src/hash-sigs/hss_alloc.c src/hash-sigs/hss_aux.c \
  src/hash-sigs/hss_common.c src/hash-sigs/hss_compute.c src/hash-sigs/hss_generate.c \
  src/hash-sigs/hss_keygen.c src/hash-sigs/hss_param.c src/hash-sigs/hss_reserve.c \
  src/hash-sigs/hss_sign.c src/hash-sigs/hss_sign_inc.c src/hash-sigs/hss_thread_single.c \
  src/hash-sigs/hss_verify.c src/hash-sigs/hss_verify_inc.c src/hash-sigs/hss_derive.c \
  src/hash-sigs/hss_zeroize.c src/hash-sigs/lm_common.c src/hash-sigs/lm_ots_common.c \
  src/hash-sigs/lm_ots_sign.c src/hash-sigs/lm_ots_verify.c src/hash-sigs/lm_verify.c \
  src/hash-sigs/endian.c src/hash-sigs/hash.c src/hash-sigs/sha256.c -lcrypto
gcc -O2 -Wall -I src/xmss-reference -o src/ref_xmss src/ref_xmss.c \
  src/xmss-reference/params.c src/xmss-reference/hash.c src/xmss-reference/fips202.c \
  src/xmss-reference/hash_address.c src/xmss-reference/randombytes.c \
  src/xmss-reference/wots.c src/xmss-reference/xmss.c src/xmss-reference/xmss_core.c \
  src/xmss-reference/xmss_commons.c src/xmss-reference/utils.c -lcrypto

# --- 4. Python venv ---
if [ ! -x venv/bin/python ]; then
  echo "creating venv and installing slh-dsa from bundled wheel ..."
  python3 -m venv venv
  venv/bin/pip install --quiet --no-index --find-links src slh-dsa==0.2.5
fi
venv/bin/python -c "from importlib.metadata import version; print('slh-dsa', version('slh-dsa'))"

# --- 5. benchmark + adversarial harness ---
mkdir -p "$OUT"
echo "running benchmark harness -> $OUT ..."
venv/bin/python src/benchmark.py --driver src/stfl_driver --pq-driver src/pq_driver \
  --ref-lms src/ref_lms --ref-xmss src/ref_xmss --outdir "$OUT" --python venv/bin/python

# --- 6. remediation: reproduce + regression test ---
echo "reproducing the failure mode -> $OUT/remediation-before.log ..."
venv/bin/python remediation/reproduce_weakness.py | tee "$OUT/remediation-before.log"
echo "running remediation regression test -> $OUT/remediation-after.log ..."
venv/bin/python remediation/test_remediation.py --driver src/stfl_driver | tee "$OUT/remediation-after.log"

# --- 7. rendered page + evidence summary ---
echo "generating docs/index.html ..."
mkdir -p docs
venv/bin/python src/generate_docs.py --results "$OUT/results.json" --out docs/index.html
echo "generating evidence.json ..."
venv/bin/python src/make_evidence.py --results "$OUT/results.json" \
  --before-log "$OUT/remediation-before.log" --after-log "$OUT/remediation-after.log"

# --- 8. digests ---
bash scripts/regen_digests.sh
echo "=== done: $RUN ==="
echo "log:      $OUT/benchmark-run.log"
echo "results:  $OUT/results.json"
echo "evidence: evidence.json"
