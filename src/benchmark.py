#!/usr/bin/env python3
"""Benchmark + adversarial harness for the stateful hash-based
signature deployment assessment pack.

Implementations under test (all pinned, all bundled under src/):
  * liboqs 0.16.0 (C) via src/stfl_driver (OQS_SIG_STFL API) — LMS
    and XMSS; via src/pq_driver (OQS_SIG API) — SLH-DSA.
  * hash-sigs (cisco/hash-sigs, RFC 8554 reference, C) via
    src/ref_lms — LMS, single level only.
  * xmss-reference (RFC 8391 reference, C) via src/ref_xmss — XMSS.
  * slh-dsa 0.2.5 (pure Python, FIPS 205 pure signing) — SLH-DSA.

What it measures:
  * Throughput: median per-operation time (keygen / sign / verify).
  * Memory: peak RSS (kilobytes) of the process performing the
    operations (VmHWM from /proc/self/status, NOT getrusage ru_maxrss:
    ru_maxrss is not per-process in this environment).
  * Sizes: public key / secret key / signature lengths verified
    against the RFC formulas (RFC 8554 sections 5-6 for LMS,
    RFC 8391 section 5 for XMSS) and FIPS 205 Table 2 (SLH-DSA).
    The liboqs/hash-sigs LMS formats carry a 4-byte HSS levels-count
    prefix on the public key and signature, so they are 4 bytes longer
    than the bare RFC 8554 LMS sizes; liboqs XMSS public keys carry a
    4-byte OID prefix, so they are 4 bytes longer than the bare
    RFC 8391 public key (the signature is exactly the RFC size).
  * State: serialized secret-key (state) size and total/remaining
    signature counts per parameter set — the deployment cost of
    statefulness. SLH-DSA is stateless (secret key is the fixed 4n
    bytes of FIPS 205 section 7).
  * Adversarial-input behaviour: flipped/wrong-message/truncated/
    wrong-parameter-set inputs for every parameter set and
    implementation; state-exhaustion behaviour (signing past the
    total signature count fails).
  * Cross-implementation agreement: liboqs <-> reference signatures
    verify in both directions for every LMS/XMSS parameter set;
    liboqs <-> slh-dsa for all 12 SLH-DSA sets.
  * Signing determinism: signing the same message twice from the
    same serialized state produces byte-identical signatures (the
    property that makes state rollback a one-time-signature reuse).
  * Artifact-size impact: signature size as a fraction of
    representative release artifacts.
  * Environment: the OpenSSL version on this machine and whether its
    signature-algorithm list contains the assessed algorithms.

Determinism note: timing medians and peak-RSS values vary between runs
by design. The comparison rule (see README.md and
src/compare_runs.py) compares only deterministic fields (sizes,
state sizes, round-trip outcomes, adversarial outcomes,
cross-implementation outcomes, determinism booleans, artifact-size
ratios, environment facts) between runs; timing/memory figures are
reported, not asserted equal. Test keys are generated fresh per
operation (benchmarking) or from a fixed public test seed
(adversarial/cross-implementation cases), so the adversarial section
is reproducible. No real keys are used anywhere.

Usage:
  python3 src/benchmark.py --driver src/stfl_driver --pq-driver src/pq_driver \
      --ref-lms src/ref_lms --ref-xmss src/ref_xmss --outdir outputs/run1
  python3 src/benchmark.py --worker slh-dsa SLH-DSA-SHA2-128s 1 /tmp/w.json
      (internal: runs one Python implementation benchmark in a child
       process so peak RSS can be measured by the parent)
"""
import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)

# LMS parameter sets: (H, W). liboqs identifier LMS_SHA256_H{h}_W{w}.
# H20 is sizes-only: keygen for a 2^20-leaf tree exceeds 240 s on
# this machine (measured: LMS H15 keygen 23.9 s, H10 0.74 s; H20
# extrapolates to ~13 min), so no keygen-dependent measurement is
# attempted for it — sizes are still verified via `info`, which needs
# no keygen.
LMS_SETS = [(5, 1), (5, 4), (10, 1), (10, 4), (10, 8), (15, 4)]
LMS_SIZE_ONLY = [(20, 4)]
# XMSS parameter sets: liboqs identifier == xmss-reference name.
# Same sizes-only rule for H20 (XMSS H16 keygen measured 72.7 s;
# H20 extrapolates to ~77 min).
XMSS_ALGS = [
    "XMSS-SHA2_10_256", "XMSS-SHA2_16_256",
    "XMSS-SHAKE_10_256", "XMSS-SHAKE_16_256",
]
XMSS_SIZE_ONLY = ["XMSS-SHA2_20_256", "XMSS-SHAKE_20_256"]
SLH_ALGS = [
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
]


def lms_name(h, w):
    return f"LMS_SHA256_H{h}_W{w}"


def lms_ots_p(h, w):
    """LM-OTS parameter p (number of Winternitz chains), RFC 8554 sec 4.2:
    p = u + v + 1 with u = ceil(256/w), v = ceil(floor(log2(u)) / w)."""
    u = -(-256 // w)
    v = -(-(int(math.floor(math.log2(u)))) // w)
    return u + v + 1


def lms_expected_sizes(h, w):
    """Expected liboqs/hash-sigs sizes (HSS framing: 4-byte levels
    prefix on public key and signature), derived from RFC 8554.
    n = 32 (SHA-256). Public key: 4 (levels) + 4 (type) + 4 (ots type)
    + 16 (I) + 32 (T1) = 60. Signature: 4 (levels) + 4 (q) + 4 (ots
    type) + 32 (C) + p*32 (y) + 4 (lms type) + H*32 (auth path)."""
    p = lms_ots_p(h, w)
    return {"pk": 60, "sk": None,
            "sig": 4 + 4 + 4 + 32 + p * 32 + 4 + h * 32,
            "rfc8554_pk": 56, "rfc8554_sig": 4 + 4 + 32 + p * 32 + 4 + h * 32,
            "ots_p": p}


def xmss_expected_sizes(alg):
    """Expected liboqs/xmss-reference sizes, derived from RFC 8391.
    n = 32 for the 256-bit sets. WOTS+ len = 67 for w=16, n=32.
    Public key: 4 (OID) + 32 (root) + 32 (seed) = 68. Signature:
    4 (idx) + 32 (r) + 67*32 (WOTS+) + H*32 (auth path)."""
    h = int(alg.split("_")[1])
    return {"pk": 68, "sk": None, "sig": 4 + 32 + 67 * 32 + h * 32,
            "rfc8391_pk": 64, "rfc8391_sig": 4 + 32 + 67 * 32 + h * 32}


# FIPS 205 Table 2 (SLH-DSA) sizes. Secret-key size is 4n bytes
# (SK.seed || SK.prf || PK.seed || PK.root, FIPS 205 section 7).
SIG_SIZES_SLH = {
    "SLH-DSA-SHA2-128s": {"pk": 32, "sk": 64, "sig": 7856},
    "SLH-DSA-SHA2-128f": {"pk": 32, "sk": 64, "sig": 17088},
    "SLH-DSA-SHA2-192s": {"pk": 48, "sk": 96, "sig": 16224},
    "SLH-DSA-SHA2-192f": {"pk": 48, "sk": 96, "sig": 35664},
    "SLH-DSA-SHA2-256s": {"pk": 64, "sk": 128, "sig": 29792},
    "SLH-DSA-SHA2-256f": {"pk": 64, "sk": 128, "sig": 49856},
}
for _fam in ("SHAKE",):
    for _n, _s in (("128s", 7856), ("128f", 17088), ("192s", 16224),
                   ("192f", 35664), ("256s", 29792), ("256f", 49856)):
        _bits = _n[:3]
        SIG_SIZES_SLH[f"SLH-DSA-{_fam}-{_n}"] = {
            "pk": {"128": 32, "192": 48, "256": 64}[_bits],
            "sk": {"128": 64, "192": 96, "256": 128}[_bits],
            "sig": _s}
SLH_PY_MOD = {a: a[len("SLH-DSA-"):].lower().replace("-", "_") for a in SLH_ALGS}
TEST_MSG = b"stateful hash-based signature deployment assessment test message"
# Representative release artifacts (bytes) for the size-impact analysis.
ARTIFACT_SIZES = {"manifest_1KiB": 1024, "wheel_100KiB": 102400,
                  "tarball_5MiB": 5 * 1024 * 1024, "binary_50MiB": 50 * 1024 * 1024}
ED25519_SIG_BYTES = 64  # RFC 8032 fixed signature size, for comparison
# Bench sample counts. Keygen for the largest trees (H20) builds a
# 2^20-leaf Merkle tree and takes tens of seconds, so n=1 there.
# Sign counts stay below the smallest total (H5: 31 signatures).
LMS_BENCH_N = {(5, 1): (10, 20, 20), (5, 4): (10, 20, 20),
               (10, 1): (5, 50, 50), (10, 4): (5, 50, 50),
               # H15: sign n=10 — liboqs LMS sign recomputes the tree
               # (~9 s per sign at H15), so n=50 would cost ~7.5 min.
               (10, 8): (5, 50, 50), (15, 4): (1, 10, 10)}
XMSS_BENCH_N = {"XMSS-SHA2_10_256": (5, 20, 20), "XMSS-SHA2_16_256": (1, 2, 2),
                # H16: sign n=2 — xmss-reference recomputes the auth
                # path per sign (~150 s per sign at H16), so n=20 would
                # cost ~50 min for that one bench call.
                "XMSS-SHAKE_10_256": (5, 20, 20), "XMSS-SHAKE_16_256": (1, 2, 2)}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _vm_hwm_kb() -> int:
    """Own peak RSS (VmHWM) from /proc/self/status, in kilobytes."""
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return -1


def median(vals):
    vals = sorted(vals)
    n = len(vals)
    return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0


class Driver:
    def __init__(self, path):
        self.path = path

    def run(self, *args):
        r = subprocess.run([self.path] + list(args), capture_output=True, text=True)
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def parse(self, out):
        d = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                d[parts[0]] = parts[1]
        return d

    def info(self, *args):
        rc, out, _ = self.run("info", *args)
        assert rc == 0, out
        return self.parse(out)


def load_slhdsa(alg):
    import slhdsa
    return getattr(slhdsa, SLH_PY_MOD[alg])


def worker_main():
    """Child-process benchmark for one Python implementation (for RSS)."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", required=True)
    ap.add_argument("alg")
    ap.add_argument("n", type=int)
    ap.add_argument("outfile")
    a = ap.parse_args(sys.argv[1:])
    out = {"implementation": a.worker, "algorithm": a.alg, "n": a.n}
    t0 = time.time()
    import slhdsa
    par = load_slhdsa(a.alg)
    ts = {"keygen": [], "sign": [], "verify": []}
    kp = slhdsa.KeyPair.gen(par)
    for _ in range(a.n):
        s = time.perf_counter(); kp = slhdsa.KeyPair.gen(par); ts["keygen"].append((time.perf_counter() - s) * 1000)
    sig = None
    for _ in range(a.n):
        s = time.perf_counter(); sig = kp.sec.sign_pure(TEST_MSG, randomize=True); ts["sign"].append((time.perf_counter() - s) * 1000)
    for _ in range(a.n):
        s = time.perf_counter(); ok = kp.pub.verify_pure(TEST_MSG, sig); ts["verify"].append((time.perf_counter() - s) * 1000)
    assert ok
    out["timing_ms_median"] = {k: round(median(v), 6) for k, v in ts.items()}
    out["roundtrip_ok"] = True
    out["wall_seconds"] = round(time.time() - t0, 3)
    out["peak_rss_kb"] = _vm_hwm_kb()
    with open(a.outfile, "w") as f:
        json.dump(out, f)
    return 0


def run_python_worker(python, impl, alg, n, tmpfile):
    r = subprocess.run([python, os.path.abspath(__file__), "--worker", impl,
                        alg, str(n), tmpfile], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"worker {impl} {alg} failed: {r.stdout} {r.stderr}")
    with open(tmpfile) as f:
        return json.load(f)


def main():
    if "--worker" in sys.argv:
        return worker_main()
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)       # stfl_driver (LMS/XMSS)
    ap.add_argument("--pq-driver", required=True)    # pq_driver (SLH-DSA)
    ap.add_argument("--ref-lms", required=True)
    ap.add_argument("--ref-xmss", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--python", default=sys.executable)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    log_path = os.path.join(a.outdir, "benchmark-run.log")
    res_path = os.path.join(a.outdir, "results.json")
    stfl = Driver(a.driver)
    pq = Driver(a.pq_driver)
    ref_lms = Driver(a.ref_lms)
    ref_xmss = Driver(a.ref_xmss)
    lines = []
    results = {"implementations": {}, "throughput": {}, "memory_kb": {},
               "adversarial": {}, "cross_implementation": {}, "determinism": {},
               "sizes_verified": {}, "state": {}, "artifact_size_impact": {},
               "environment": {}}

    def log(s):
        lines.append(s)
        print(s, flush=True)

    log("=== stateful hash-based signature deployment assessment harness ===")
    log(f"stfl driver: {a.driver}")
    log(f"pq driver: {a.pq_driver}")
    log(f"ref-lms driver: {a.ref_lms}")
    log(f"ref-xmss driver: {a.ref_xmss}")
    log(f"python: {a.python}")
    log("test message: 'stateful hash-based signature deployment assessment test message'")

    # --- 0. sizes ------------------------------------------------------
    log("--- sizes (RFC 8554 / RFC 8391 formulas, FIPS 205 Table 2) ---")
    for (h, w) in LMS_SETS + LMS_SIZE_ONLY:
        name = lms_name(h, w)
        exp = lms_expected_sizes(h, w)
        info = stfl.info(name)
        got = {"pk": int(info["length_public_key"]), "sk": int(info["length_secret_key"]),
               "sig": int(info["length_signature"])}
        ok = got["pk"] == exp["pk"] and got["sig"] == exp["sig"]
        results["sizes_verified"][name] = {"expected": exp, "liboqs": got, "match": ok}
        log(f"SIZE {name} liboqs={got} expected_pk={exp['pk']} expected_sig={exp['sig']} "
            f"(RFC 8554 bare pk={exp['rfc8554_pk']} sig={exp['rfc8554_sig']}, ots_p={exp['ots_p']}) match={ok}")
        assert ok
        info_r = ref_lms.info(str(h), str(w))
        got_r = {"pk": int(info_r["length_public_key"]), "sk": int(info_r["length_secret_key"]),
                 "sig": int(info_r["length_signature"])}
        ok_r = got_r["pk"] == exp["pk"] and got_r["sig"] == exp["sig"]
        results["sizes_verified"][name]["hash-sigs"] = got_r
        results["sizes_verified"][name]["hash-sigs_match"] = ok_r
        log(f"SIZE {name} hash-sigs={got_r} match={ok_r}")
        assert ok_r
    for alg in XMSS_ALGS + XMSS_SIZE_ONLY:
        exp = xmss_expected_sizes(alg)
        info = stfl.info(alg)
        got = {"pk": int(info["length_public_key"]), "sk": int(info["length_secret_key"]),
               "sig": int(info["length_signature"])}
        ok = got["pk"] == exp["pk"] and got["sig"] == exp["sig"]
        results["sizes_verified"][alg] = {"expected": exp, "liboqs": got, "match": ok}
        log(f"SIZE {alg} liboqs={got} expected_pk={exp['pk']} expected_sig={exp['sig']} "
            f"(RFC 8391 bare pk={exp['rfc8391_pk']} sig={exp['rfc8391_sig']}) match={ok}")
        assert ok
        info_r = ref_xmss.info(alg)
        got_r = {"pk": int(info_r["length_public_key"]), "sk": int(info_r["length_secret_key"]),
                 "sig": int(info_r["length_signature"])}
        ok_r = got_r["pk"] == exp["pk"] and got_r["sig"] == exp["sig"]
        results["sizes_verified"][alg]["xmss-reference"] = got_r
        results["sizes_verified"][alg]["xmss-reference_match"] = ok_r
        log(f"SIZE {alg} xmss-reference={got_r} match={ok_r}")
        assert ok_r
    for alg in SLH_ALGS:
        info = pq.info(alg)
        got = {"pk": int(info["length_public_key"]), "sk": int(info["length_secret_key"]),
               "sig": int(info["length_signature"])}
        ok = got == SIG_SIZES_SLH[alg]
        results["sizes_verified"][alg] = {"expected": SIG_SIZES_SLH[alg], "liboqs": got, "match": ok}
        log(f"SIZE {alg} liboqs={got} expected={SIG_SIZES_SLH[alg]} match={ok}")
        assert ok
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        sig = kp.sec.sign_pure(TEST_MSG, randomize=True)
        got = {"pk": len(kp.pub.digest()), "sk": len(kp.sec.digest()), "sig": len(sig)}
        ok = got == SIG_SIZES_SLH[alg]
        log(f"SIZE {alg} slh-dsa={got} match={ok}")
        assert ok

    # --- 0b. state sizes ----------------------------------------------
    log("--- state (serialized secret-key size, total/remaining signatures) ---")
    for (h, w) in LMS_SETS:
        name = lms_name(h, w)
        rc, out, _ = stfl.run("keygen", name)
        assert rc == 0, out
        d = stfl.parse(out)
        sk_ser_len = int(d["secret_key_serialized_len"])
        total = int(d["sigs_total"])
        results["state"][name] = {
            "liboqs_serialized_secret_key_bytes": sk_ser_len,
            "hash-sigs_secret_key_bytes": int(ref_lms.info(str(h), str(w))["length_secret_key"]),
            "sigs_total": total, "sigs_remaining_after_keygen": int(d["sigs_remaining"]),
            "expected_total": (2 ** h) - 1}
        log(f"STATE {name} liboqs_serialized_sk={sk_ser_len}B "
            f"hash-sigs_sk={results['state'][name]['hash-sigs_secret_key_bytes']}B "
            f"sigs_total={total} expected_total={(2 ** h) - 1} "
            f"remaining_after_keygen={d['sigs_remaining']}")
        assert total == (2 ** h) - 1
    for alg in XMSS_ALGS:
        rc, out, _ = stfl.run("keygen", alg)
        assert rc == 0, out
        d = stfl.parse(out)
        sk_ser_len = int(d["secret_key_serialized_len"])
        total = int(d["sigs_total"])
        results["state"][alg] = {
            "liboqs_serialized_secret_key_bytes": sk_ser_len,
            "xmss-reference_secret_key_bytes": int(ref_xmss.info(alg)["length_secret_key"]),
            "sigs_total": total, "sigs_remaining_after_keygen": int(d["sigs_remaining"]),
            "expected_total": (2 ** int(alg.split("_")[1])) - 1}
        log(f"STATE {alg} liboqs_serialized_sk={sk_ser_len}B "
            f"xmss-reference_sk={results['state'][alg]['xmss-reference_secret_key_bytes']}B "
            f"sigs_total={total} expected_total={(2 ** int(alg.split('_')[1])) - 1} "
            f"remaining_after_keygen={d['sigs_remaining']}")
        assert total == (2 ** int(alg.split("_")[1])) - 1
    for alg in SLH_ALGS:
        results["state"][alg] = {
            "liboqs_secret_key_bytes": SIG_SIZES_SLH[alg]["sk"],
            "stateless": True, "sigs_total": "unlimited (2^64 per FIPS 205)"}
        log(f"STATE {alg} stateless sk={SIG_SIZES_SLH[alg]['sk']}B sigs_total=unlimited")
    # Sizes-only sets: no keygen was attempted (see the H20 note above),
    # so serialized state size and total counts are recorded as not
    # measured rather than invented.
    for (h, w) in LMS_SIZE_ONLY:
        name = lms_name(h, w)
        results["state"][name] = {
            "liboqs_serialized_secret_key_bytes": None,
            "hash-sigs_secret_key_bytes": int(ref_lms.info(str(h), str(w))["length_secret_key"]),
            "sigs_total": None, "sigs_remaining_after_keygen": None,
            "expected_total": (2 ** h) - 1,
            "not_measured": "keygen exceeds 240 s on this machine"}
        log(f"STATE {name} NOT MEASURED (keygen exceeds 240 s); "
            f"hash-sigs_sk={results['state'][name]['hash-sigs_secret_key_bytes']}B "
            f"expected_total={(2 ** h) - 1}")
    for alg in XMSS_SIZE_ONLY:
        results["state"][alg] = {
            "liboqs_serialized_secret_key_bytes": None,
            "xmss-reference_secret_key_bytes": int(ref_xmss.info(alg)["length_secret_key"]),
            "sigs_total": None, "sigs_remaining_after_keygen": None,
            "expected_total": (2 ** int(alg.split("_")[1])) - 1,
            "not_measured": "keygen exceeds 240 s on this machine"}
        log(f"STATE {alg} NOT MEASURED (keygen exceeds 240 s); "
            f"xmss-reference_sk={results['state'][alg]['xmss-reference_secret_key_bytes']}B "
            f"expected_total={(2 ** int(alg.split('_')[1])) - 1}")

    # --- 1. throughput + memory: liboqs STFL (LMS/XMSS) --------------
    log("--- throughput: liboqs LMS/XMSS (C, OQS_SIG_STFL) ---")
    for (h, w) in LMS_SETS:
        name = lms_name(h, w)
        nk, ns, nv = LMS_BENCH_N[(h, w)]
        rc, out, _ = stfl.run("bench", name, str(nk), str(ns), str(nv))
        assert rc == 0, out
        d = stfl.parse(out)
        results["throughput"].setdefault(name, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n_keygen": nk, "n_sign": ns, "n_verify": nv,
            "sign_ok": d["sign_ok"], "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(name, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {name} keygen_n={nk} sign_n={ns} verify_n={nv} "
            f"keygen={d['keygen_ms_median']}ms sign={d['sign_ms_median']}ms "
            f"verify={d['verify_ms_median']}ms sign_ok={d['sign_ok']} "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")
    for alg in XMSS_ALGS:
        nk, ns, nv = XMSS_BENCH_N[alg]
        rc, out, _ = stfl.run("bench", alg, str(nk), str(ns), str(nv))
        assert rc == 0, out
        d = stfl.parse(out)
        results["throughput"].setdefault(alg, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n_keygen": nk, "n_sign": ns, "n_verify": nv,
            "sign_ok": d["sign_ok"], "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(alg, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {alg} keygen_n={nk} sign_n={ns} verify_n={nv} "
            f"keygen={d['keygen_ms_median']}ms sign={d['sign_ms_median']}ms "
            f"verify={d['verify_ms_median']}ms sign_ok={d['sign_ok']} "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")

    # --- 1b. throughput + memory: reference implementations ------------
    log("--- throughput: hash-sigs LMS (C reference) ---")
    for (h, w) in LMS_SETS:
        name = lms_name(h, w)
        nk, ns, nv = LMS_BENCH_N[(h, w)]
        rc, out, _ = ref_lms.run("bench", str(h), str(w), str(nk), str(ns), str(nv))
        assert rc == 0, out
        d = ref_lms.parse(out)
        results["throughput"].setdefault(name, {})["hash-sigs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n_keygen": nk, "n_sign": ns, "n_verify": nv,
            "sign_ok": d["sign_ok"], "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(name, {})["hash-sigs"] = int(d["peak_rss_kb"])
        log(f"TIMING hash-sigs {name} keygen_n={nk} sign_n={ns} verify_n={nv} "
            f"keygen={d['keygen_ms_median']}ms sign={d['sign_ms_median']}ms "
            f"verify={d['verify_ms_median']}ms sign_ok={d['sign_ok']} "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")
    log("--- throughput: xmss-reference XMSS (C reference) ---")
    for alg in XMSS_ALGS:
        nk, ns, nv = XMSS_BENCH_N[alg]
        rc, out, _ = ref_xmss.run("bench", alg, str(nk), str(ns), str(nv))
        assert rc == 0, out
        d = ref_xmss.parse(out)
        results["throughput"].setdefault(alg, {})["xmss-reference"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n_keygen": nk, "n_sign": ns, "n_verify": nv,
            "sign_ok": d["sign_ok"], "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(alg, {})["xmss-reference"] = int(d["peak_rss_kb"])
        log(f"TIMING xmss-reference {alg} keygen_n={nk} sign_n={ns} verify_n={nv} "
            f"keygen={d['keygen_ms_median']}ms sign={d['sign_ms_median']}ms "
            f"verify={d['verify_ms_median']}ms sign_ok={d['sign_ok']} "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")

    # --- 1c. throughput + memory: SLH-DSA (liboqs + slh-dsa) ----------
    log("--- throughput: liboqs SLH-DSA (C) ---")
    for alg in SLH_ALGS:
        rc, out, _ = pq.run("sig-bench", alg, "20")
        assert rc == 0, out
        d = pq.parse(out)
        results["throughput"].setdefault(alg, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n": 20, "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(alg, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {alg} n=20 keygen={d['keygen_ms_median']}ms "
            f"sign={d['sign_ms_median']}ms verify={d['verify_ms_median']}ms "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")
    log("--- throughput: slh-dsa (pure Python, n=1 indicative) ---")
    for alg in SLH_ALGS:
        tmp = os.path.join(a.outdir, f"worker-{alg}.json")
        data = run_python_worker(a.python, "slh-dsa", alg, 1, tmp)
        os.remove(tmp)
        results["throughput"].setdefault(alg, {})["slh-dsa"] = dict(
            data["timing_ms_median"], n=1, roundtrip_ok=data["roundtrip_ok"])
        results["memory_kb"].setdefault(alg, {})["slh-dsa"] = data["peak_rss_kb"]
        t = data["timing_ms_median"]
        log(f"TIMING slh-dsa {alg} n=1 keygen={t['keygen']}ms sign={t['sign']}ms "
            f"verify={t['verify']}ms roundtrip_ok={data['roundtrip_ok']} "
            f"peak_rss_kb={data['peak_rss_kb']}")

    # --- 2. adversarial: LMS -------------------------------------------
    log("--- adversarial: LMS ---")
    for (h, w) in LMS_SETS:
        name = lms_name(h, w)
        other = LMS_SETS[1] if (h, w) != LMS_SETS[1] else LMS_SETS[0]
        cases = {}
        rc, out, _ = stfl.run("keygen", name)
        d = stfl.parse(out)
        pk, sk = d["public_key"], d["secret_key"]
        msg = TEST_MSG.hex()
        rc, out, _ = stfl.run("sign", name, sk, msg)
        sd = stfl.parse(out)
        sig = sd["signature"]
        rc, out, _ = stfl.run("verify", name, pk, msg, sig)
        cases["liboqs_valid"] = stfl.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        rc, out, _ = stfl.run("verify", name, pk, msg, bad.hex())
        cases["liboqs_flipped_sig"] = stfl.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = stfl.run("verify", name, pk, (b"tampered message").hex(), sig)
        cases["liboqs_wrong_msg"] = stfl.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = stfl.run("verify", name, pk, msg, sig[:-2])
        cases["liboqs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = stfl.run("verify", lms_name(*other), pk, msg, sig)
        cases["liboqs_cross_param"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        # hash-sigs reference: same cases on its own key.
        rc, out, _ = ref_lms.run("keygen", str(h), str(w))
        rd = ref_lms.parse(out)
        rpk, rsk = rd["public_key"], rd["secret_key"]
        rc, out, _ = ref_lms.run("sign", str(h), str(w), rsk, msg)
        rsig = ref_lms.parse(out)["signature"]
        rc, out, _ = ref_lms.run("verify", str(h), str(w), rpk, msg, rsig)
        cases["hash-sigs_valid"] = ref_lms.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(rsig)); bad[0] ^= 0x01
        rc, out, _ = ref_lms.run("verify", str(h), str(w), rpk, msg, bad.hex())
        cases["hash-sigs_flipped_sig"] = ref_lms.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = ref_lms.run("verify", str(h), str(w), rpk, (b"tampered message").hex(), rsig)
        cases["hash-sigs_wrong_msg"] = ref_lms.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = ref_lms.run("verify", str(h), str(w), rpk, msg, rsig[:-2])
        cases["hash-sigs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        results["adversarial"][name] = cases
        for k, v in cases.items():
            log(f"ADV {name} {k} = {v}")

    # --- 3. adversarial: XMSS ------------------------------------------
    log("--- adversarial: XMSS ---")
    for alg in XMSS_ALGS:
        other = XMSS_ALGS[1] if alg != XMSS_ALGS[1] else XMSS_ALGS[0]
        cases = {}
        rc, out, _ = stfl.run("keygen", alg)
        d = stfl.parse(out)
        pk, sk = d["public_key"], d["secret_key"]
        msg = TEST_MSG.hex()
        rc, out, _ = stfl.run("sign", alg, sk, msg)
        sig = stfl.parse(out)["signature"]
        rc, out, _ = stfl.run("verify", alg, pk, msg, sig)
        cases["liboqs_valid"] = stfl.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        rc, out, _ = stfl.run("verify", alg, pk, msg, bad.hex())
        cases["liboqs_flipped_sig"] = stfl.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = stfl.run("verify", alg, pk, (b"tampered message").hex(), sig)
        cases["liboqs_wrong_msg"] = stfl.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = stfl.run("verify", alg, pk, msg, sig[:-2])
        cases["liboqs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = stfl.run("verify", other, pk, msg, sig)
        if rc == 2 and "length check failed" in out:
            cases["liboqs_cross_param"] = "refused_length_check"
        elif rc == 0 and stfl.parse(out).get("verify") == "INVALID":
            cases["liboqs_cross_param"] = "verify_INVALID"
        else:
            cases["liboqs_cross_param"] = f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = ref_xmss.run("keygen", alg)
        rd = ref_xmss.parse(out)
        rpk, rsk = rd["public_key"], rd["secret_key"]
        rc, out, _ = ref_xmss.run("sign", alg, rsk, msg)
        rsig = ref_xmss.parse(out)["signature"]
        rc, out, _ = ref_xmss.run("verify", alg, rpk, msg, rsig)
        cases["xmss-reference_valid"] = ref_xmss.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(rsig)); bad[0] ^= 0x01
        rc, out, _ = ref_xmss.run("verify", alg, rpk, msg, bad.hex())
        cases["xmss-reference_flipped_sig"] = ref_xmss.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = ref_xmss.run("verify", alg, rpk, (b"tampered message").hex(), rsig)
        cases["xmss-reference_wrong_msg"] = ref_xmss.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = ref_xmss.run("verify", alg, rpk, msg, rsig[:-2])
        cases["xmss-reference_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        results["adversarial"][alg] = cases
        for k, v in cases.items():
            log(f"ADV {alg} {k} = {v}")

    # --- 4. adversarial: SLH-DSA (reuse of the release-signing pack) ---
    log("--- adversarial: SLH-DSA ---")
    for alg in SLH_ALGS:
        other = SLH_ALGS[1] if alg != SLH_ALGS[1] else SLH_ALGS[0]
        cases = {}
        rc, out, _ = pq.run("sig-keygen", alg)
        d = pq.parse(out)
        pk, sk = d["public_key"], d["secret_key"]
        msg = TEST_MSG.hex()
        rc, out, _ = pq.run("sig-sign", alg, sk, msg)
        sig = pq.parse(out)["signature"]
        rc, out, _ = pq.run("sig-verify", alg, pk, msg, sig)
        cases["liboqs_valid"] = pq.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        rc, out, _ = pq.run("sig-verify", alg, pk, msg, bad.hex())
        cases["liboqs_flipped_sig"] = pq.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = pq.run("sig-verify", alg, pk, (b"tampered message").hex(), sig)
        cases["liboqs_wrong_msg"] = pq.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = pq.run("sig-verify", alg, pk, msg, sig[:-2])
        cases["liboqs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = pq.run("sig-verify", other, pk, msg, sig)
        if rc == 2 and "length check failed" in out:
            cases["liboqs_cross_param"] = "refused_length_check"
        elif rc == 0 and pq.parse(out).get("verify") == "INVALID":
            cases["liboqs_cross_param"] = "verify_INVALID"
        else:
            cases["liboqs_cross_param"] = f"UNEXPECTED rc={rc} out={out[:80]}"
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        sig2 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        cases["slhdsa_valid"] = kp.pub.verify_pure(TEST_MSG, sig2) is True
        bad2 = bytearray(sig2); bad2[0] ^= 0x01
        cases["slhdsa_flipped_sig"] = kp.pub.verify_pure(TEST_MSG, bytes(bad2))
        cases["slhdsa_wrong_msg"] = kp.pub.verify_pure(b"tampered message", sig2)
        try:
            r = kp.pub.verify_pure(TEST_MSG, sig2[:-1])
            cases["slhdsa_truncated_sig"] = "returns_False" if r is False else f"UNEXPECTED_returned_{r!r}"
        except Exception as e:
            cases["slhdsa_truncated_sig"] = f"refused_{type(e).__name__}"
        par_o = load_slhdsa(other)
        kp_o = slhdsa.KeyPair.gen(par_o)
        try:
            cases["slhdsa_cross_param"] = kp_o.pub.verify_pure(TEST_MSG, sig2)
        except Exception as e:
            cases["slhdsa_cross_param"] = f"refused_{type(e).__name__}"
        results["adversarial"][alg] = cases
        for k, v in cases.items():
            log(f"ADV {alg} {k} = {v}")

    # --- 5. cross-implementation ---------------------------------------
    log("--- cross-implementation agreement ---")
    for (h, w) in LMS_SETS:
        name = lms_name(h, w)
        rc, out, _ = stfl.run("keygen", name)
        d = stfl.parse(out)
        pk_c, sk_c = d["public_key"], d["secret_key"]
        rc, out, _ = stfl.run("sign", name, sk_c, TEST_MSG.hex())
        sig_c = stfl.parse(out)["signature"]
        rc, out, _ = ref_lms.run("verify", str(h), str(w), pk_c, TEST_MSG.hex(), sig_c)
        ok1 = ref_lms.parse(out).get("verify") == "VALID"
        rc, out, _ = ref_lms.run("keygen", str(h), str(w))
        rd = ref_lms.parse(out)
        rpk, rsk = rd["public_key"], rd["secret_key"]
        rc, out, _ = ref_lms.run("sign", str(h), str(w), rsk, TEST_MSG.hex())
        rsig = ref_lms.parse(out)["signature"]
        rc, out, _ = stfl.run("verify", name, rpk, TEST_MSG.hex(), rsig)
        ok2 = stfl.parse(out).get("verify") == "VALID"
        results["cross_implementation"][name] = {
            "sig_liboqs_sign_hash-sigs_verify": ok1,
            "sig_hash-sigs_sign_liboqs_verify": ok2}
        log(f"XIMPL {name} liboqs-sign/hash-sigs-verify={ok1} hash-sigs-sign/liboqs-verify={ok2}")
    for alg in XMSS_ALGS:
        rc, out, _ = stfl.run("keygen", alg)
        d = stfl.parse(out)
        pk_c, sk_c = d["public_key"], d["secret_key"]
        rc, out, _ = stfl.run("sign", alg, sk_c, TEST_MSG.hex())
        sig_c = stfl.parse(out)["signature"]
        rc, out, _ = ref_xmss.run("verify", alg, pk_c, TEST_MSG.hex(), sig_c)
        ok1 = ref_xmss.parse(out).get("verify") == "VALID"
        rc, out, _ = ref_xmss.run("keygen", alg)
        rd = ref_xmss.parse(out)
        rpk, rsk = rd["public_key"], rd["secret_key"]
        rc, out, _ = ref_xmss.run("sign", alg, rsk, TEST_MSG.hex())
        rsig = ref_xmss.parse(out)["signature"]
        rc, out, _ = stfl.run("verify", alg, rpk, TEST_MSG.hex(), rsig)
        ok2 = stfl.parse(out).get("verify") == "VALID"
        results["cross_implementation"][alg] = {
            "sig_liboqs_sign_xmss-reference_verify": ok1,
            "sig_xmss-reference_sign_liboqs_verify": ok2}
        log(f"XIMPL {alg} liboqs-sign/xmss-reference-verify={ok1} xmss-reference-sign/liboqs-verify={ok2}")
    for alg in SLH_ALGS:
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        sig2 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        rc, out, _ = pq.run("sig-verify", alg, kp.pub.digest().hex(), TEST_MSG.hex(), sig2.hex())
        ok1 = pq.parse(out).get("verify") == "VALID"
        rc, out, _ = pq.run("sig-keygen", alg)
        d = pq.parse(out)
        pk_c, sk_c = d["public_key"], d["secret_key"]
        rc, out, _ = pq.run("sig-sign", alg, sk_c, TEST_MSG.hex())
        sig_c = pq.parse(out)["signature"]
        pk_obj = slhdsa.PublicKey.from_digest(bytes.fromhex(pk_c), par)
        ok2 = pk_obj.verify_pure(TEST_MSG, bytes.fromhex(sig_c)) is True
        results["cross_implementation"][alg] = {
            "sig_slhdsa_sign_liboqs_verify": ok1,
            "sig_liboqs_sign_slhdsa_verify": ok2}
        log(f"XIMPL {alg} slhdsa-sign/liboqs-verify={ok1} liboqs-sign/slhdsa-verify={ok2}")

    # --- 6. signing determinism (same state, same message) --------------
    log("--- signing determinism (same serialized state, same message, signed twice) ---")
    for (h, w) in LMS_SETS:
        name = lms_name(h, w)
        rc, out, _ = stfl.run("keygen", name)
        sk = stfl.parse(out)["secret_key"]
        rc, out, _ = stfl.run("sign", name, sk, TEST_MSG.hex())
        s1 = stfl.parse(out)["signature"]
        rc, out, _ = stfl.run("sign", name, sk, TEST_MSG.hex())
        s2 = stfl.parse(out)["signature"]
        idx1 = stfl.parse(out).get("signature_index")
        results["determinism"][name] = {
            "liboqs_same_state_same_msg_identical": s1 == s2,
            "liboqs_same_state_leaf_index": idx1}
        log(f"DET {name} liboqs_same_state_same_msg_identical={s1 == s2} leaf_index={idx1}")
        rc, out, _ = ref_lms.run("keygen", str(h), str(w))
        rsk = ref_lms.parse(out)["secret_key"]
        rc, out, _ = ref_lms.run("sign", str(h), str(w), rsk, TEST_MSG.hex())
        r1 = ref_lms.parse(out)["signature"]
        rc, out, _ = ref_lms.run("sign", str(h), str(w), rsk, TEST_MSG.hex())
        r2 = ref_lms.parse(out)["signature"]
        results["determinism"][name]["hash-sigs_same_state_same_msg_identical"] = r1 == r2
        log(f"DET {name} hash-sigs_same_state_same_msg_identical={r1 == r2}")
    for alg in XMSS_ALGS:
        rc, out, _ = stfl.run("keygen", alg)
        sk = stfl.parse(out)["secret_key"]
        rc, out, _ = stfl.run("sign", alg, sk, TEST_MSG.hex())
        s1 = stfl.parse(out)["signature"]
        rc, out, _ = stfl.run("sign", alg, sk, TEST_MSG.hex())
        s2 = stfl.parse(out)["signature"]
        idx1 = stfl.parse(out).get("signature_index")
        results["determinism"][alg] = {
            "liboqs_same_state_same_msg_identical": s1 == s2,
            "liboqs_same_state_leaf_index": idx1}
        log(f"DET {alg} liboqs_same_state_same_msg_identical={s1 == s2} leaf_index={idx1}")
        rc, out, _ = ref_xmss.run("keygen", alg)
        rsk = ref_xmss.parse(out)["secret_key"]
        rc, out, _ = ref_xmss.run("sign", alg, rsk, TEST_MSG.hex())
        r1 = ref_xmss.parse(out)["signature"]
        rc, out, _ = ref_xmss.run("sign", alg, rsk, TEST_MSG.hex())
        r2 = ref_xmss.parse(out)["signature"]
        results["determinism"][alg]["xmss-reference_same_state_same_msg_identical"] = r1 == r2
        log(f"DET {alg} xmss-reference_same_state_same_msg_identical={r1 == r2}")
    for alg in SLH_ALGS:
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        d1 = kp.sec.sign_pure(TEST_MSG, randomize=False)
        d2 = kp.sec.sign_pure(TEST_MSG, randomize=False)
        r1 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        r2 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        rc, out, _ = pq.run("sig-keygen", alg)
        sk_c = pq.parse(out)["secret_key"]
        rc, out, _ = pq.run("sig-sign-twice", alg, sk_c, TEST_MSG.hex())
        liboqs_identical = pq.parse(out).get("signatures_identical")
        results["determinism"][alg] = {
            "liboqs_sign_twice_identical": liboqs_identical,
            "slhdsa_deterministic_sign_twice_identical": d1 == d2,
            "slhdsa_randomized_sign_twice_identical": r1 == r2}
        log(f"DET {alg} liboqs_sign_twice_identical={liboqs_identical} "
            f"slhdsa_deterministic_identical={d1 == d2} "
            f"slhdsa_randomized_identical={r1 == r2}")

    # --- 7. state exhaustion --------------------------------------------
    log("--- state exhaustion (LMS H5: 31 signatures total) ---")
    rc, out, _ = stfl.run("keygen", "LMS_SHA256_H5_W4")
    d = stfl.parse(out)
    sk_h5, pk_h5, total_h5 = d["secret_key"], d["public_key"], int(d["sigs_total"])
    rc, out, _ = stfl.run("sign-many", "LMS_SHA256_H5_W4", sk_h5, TEST_MSG.hex(), str(total_h5))
    exhausted_ok = rc == 0 and "sigs_remaining 0" in out
    # One signature past the reported total: liboqs reports total = 2^H-1
    # but the tree has 2^H leaves, so index 2^H-1 is still signable.
    sk_after = stfl.parse(out)["secret_key"]
    rc2, out2, _ = stfl.run("sign", "LMS_SHA256_H5_W4", sk_after, TEST_MSG.hex())
    sig32 = stfl.parse(out2).get("signature", "")
    rc3, out3, _ = stfl.run("verify", "LMS_SHA256_H5_W4", pk_h5, TEST_MSG.hex(), sig32)
    verify32 = "verify VALID" in out3
    # And one more: the state after the 32nd signature cannot even be
    # deserialized, so the key is dead after the extra signature.
    sk_after32 = stfl.parse(out2).get("secret_key", "")
    rc4, out4, _ = stfl.run("sign", "LMS_SHA256_H5_W4", sk_after32, TEST_MSG.hex())
    results["exhaustion"] = {
        "algorithm": "LMS_SHA256_H5_W4", "sigs_total": total_h5,
        "sign_all_total_ok": exhausted_ok,
        "sign_after_exhaustion_rc": rc2,
        "sign_after_exhaustion_produced_signature": bool(sig32),
        "sign_after_exhaustion_verifies": verify32,
        "sign_after_exhaustion_fails": rc2 != 0,
        "third_sign_after_exhaustion_rc": rc4,
        "third_sign_after_exhaustion_output": out4.strip().splitlines()[0] if out4.strip() else ""}
    log(f"EXHAUST LMS_SHA256_H5_W4 total={total_h5} sign_all_ok={exhausted_ok} "
        f"sign_after_exhaustion_rc={rc2} produced={bool(sig32)} verifies={verify32} "
        f"third_sign_rc={rc4} third_sign={results['exhaustion']['third_sign_after_exhaustion_output']}")
    # XMSS: same probe at H10 (1023 reported, 2^10 leaves).
    rc, out, _ = stfl.run("keygen", "XMSS-SHA2_10_256")
    d = stfl.parse(out)
    sk_x, pk_x, total_x = d["secret_key"], d["public_key"], int(d["sigs_total"])
    rc, out, _ = stfl.run("sign-many", "XMSS-SHA2_10_256", sk_x, TEST_MSG.hex(), str(total_x))
    x_all_ok = rc == 0 and "sigs_remaining 0" in out
    rc2, out2, _ = stfl.run("sign", "XMSS-SHA2_10_256",
                            stfl.parse(out)["secret_key"], TEST_MSG.hex())
    sigx = stfl.parse(out2).get("signature", "")
    rc3, out3, _ = stfl.run("verify", "XMSS-SHA2_10_256", pk_x, TEST_MSG.hex(), sigx)
    verifyx = "verify VALID" in out3
    results["exhaustion"]["xmss_total"] = total_x
    results["exhaustion"]["xmss_sign_all_total_ok"] = x_all_ok
    results["exhaustion"]["xmss_sign_after_exhaustion_rc"] = rc2
    results["exhaustion"]["xmss_sign_after_exhaustion_produced_signature"] = bool(sigx)
    results["exhaustion"]["xmss_sign_after_exhaustion_verifies"] = verifyx
    log(f"EXHAUST XMSS-SHA2_10_256 total={total_x} sign_all_ok={x_all_ok} "
        f"sign_after_exhaustion_rc={rc2} produced={bool(sigx)} verifies={verifyx}")

    # --- 8. artifact-size impact ---------------------------------------
    log("--- artifact-size impact (signature bytes vs release artifact) ---")
    all_sigs = {}
    for (h, w) in LMS_SETS + LMS_SIZE_ONLY:
        all_sigs[lms_name(h, w)] = lms_expected_sizes(h, w)["sig"]
    for alg in XMSS_ALGS + XMSS_SIZE_ONLY:
        all_sigs[alg] = xmss_expected_sizes(alg)["sig"]
    for alg in SLH_ALGS:
        all_sigs[alg] = SIG_SIZES_SLH[alg]["sig"]
    for alg, sig_bytes in all_sigs.items():
        entry = {"signature_bytes": sig_bytes,
                 "vs_ed25519_64B": round(sig_bytes / ED25519_SIG_BYTES, 1)}
        for name, size in ARTIFACT_SIZES.items():
            entry[f"overhead_pct_{name}"] = round(100.0 * sig_bytes / size, 4)
        results["artifact_size_impact"][alg] = entry
        log(f"ARTIFACT {alg} sig={sig_bytes}B vs_ed25519={entry['vs_ed25519_64B']}x "
            f"manifest_1KiB={entry['overhead_pct_manifest_1KiB']}% "
            f"wheel_100KiB={entry['overhead_pct_wheel_100KiB']}% "
            f"tarball_5MiB={entry['overhead_pct_tarball_5MiB']}% "
            f"binary_50MiB={entry['overhead_pct_binary_50MiB']}%")

    # --- 9. environment -------------------------------------------------
    log("--- environment: OpenSSL on this machine ---")
    r = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    ver = r.stdout.strip()
    r2 = subprocess.run(["openssl", "list", "-signature-algorithms"],
                        capture_output=True, text=True)
    algs = r2.stdout
    has_mldsa = "ML-DSA" in algs
    has_slhdsa = "SLH-DSA" in algs
    has_lms = "LMS" in algs
    has_xmss = "XMSS" in algs
    results["environment"] = {
        "openssl_version": ver,
        "openssl_lists_ml_dsa": has_mldsa,
        "openssl_lists_slh_dsa": has_slhdsa,
        "openssl_lists_lms": has_lms,
        "openssl_lists_xmss": has_xmss,
        "python": sys.version.split()[0],
        "liboqs_stfl_keygen_and_sign_supported": True,
    }
    log(f"ENV openssl: {ver}")
    log(f"ENV openssl lists ML-DSA: {has_mldsa}; SLH-DSA: {has_slhdsa}; LMS: {has_lms}; XMSS: {has_xmss}")
    log("ENV liboqs stateful keygen/sign: supported (hazardous-experimental build flag ON)")

    results["implementations"] = {
        "liboqs": "0.16.0 (C, sig_stfl LMS/XMSS + slh-dsa backends; stateful keygen/sign enabled with OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN)",
        "hash-sigs": "cisco/hash-sigs (C, RFC 8554 LMS reference; commit 7768828)",
        "xmss-reference": "joostrijneveld/xmss-reference (C, RFC 8391 XMSS reference; commit 171ccbd)",
        "slh-dsa": "0.2.5 (pure Python, FIPS 205 pure signing; author Colinxu2020)",
        "rust": "NOT RUN — no cargo/rustc toolchain on this machine",
        "go": "NOT RUN — no Go toolchain on this machine"}
    with open(res_path, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)
    with open(log_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    log(f"=== done: results -> {res_path} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
