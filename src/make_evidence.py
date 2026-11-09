#!/usr/bin/env python3
"""Build evidence.json from a run's results.json + remediation logs.

Usage: python3 src/make_evidence.py --results outputs/run1/results.json
         --before-log outputs/run1/remediation-before.log
         --after-log outputs/run1/remediation-after.log
"""
import argparse
import json
import os
import re

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def count_findings():
    """Count findings by severity from findings.md headers (## F-0X — Sev:)."""
    counts = {"High": 0, "Medium": 0, "Low": 0}
    total = 0
    with open(os.path.join(PACK, "findings.md")) as f:
        for line in f:
            m = re.match(r"## F-\d+ — (High|Medium|Low)", line)
            if m:
                counts[m.group(1)] += 1
                total += 1
    return total, counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--before-log", required=True)
    ap.add_argument("--after-log", required=True)
    a = ap.parse_args()
    with open(a.results) as f:
        r = json.load(f)
    with open(a.before_log) as f:
        before = f.read()
    with open(a.after_log) as f:
        after = f.read()
    total, counts = count_findings()
    m = re.search(r"regression test: (\d+) passed, (\d+) failed", after)
    evidence = {
        "pack": "stateful-hash-based-signature-deployment-assessment",
        "implementations_benchmarked": {
            "liboqs": "0.16.0 (C, sig_stfl LMS/XMSS + slh-dsa backends; stateful keygen/sign enabled with OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN)",
            "hash-sigs": "cisco/hash-sigs (C, RFC 8554 LMS reference; commit 7768828)",
            "xmss-reference": "joostrijneveld/xmss-reference (C, RFC 8391 XMSS reference; commit 171ccbd)",
            "slh-dsa": "0.2.5 (pure Python, FIPS 205 pure signing)",
            "rust": "not run — no cargo/rustc toolchain on this machine",
            "go": "not run — no Go toolchain on this machine",
        },
        "parameter_sets": {
            "LMS": ["LMS_SHA256_H5_W1", "LMS_SHA256_H5_W4", "LMS_SHA256_H10_W1",
                    "LMS_SHA256_H10_W4", "LMS_SHA256_H10_W8", "LMS_SHA256_H15_W4",
                    "LMS_SHA256_H20_W4 (sizes only; keygen exceeds 240 s)"],
            "XMSS": ["XMSS-SHA2_10_256", "XMSS-SHA2_16_256",
                     "XMSS-SHA2_20_256 (sizes only; keygen exceeds 240 s)",
                     "XMSS-SHAKE_10_256", "XMSS-SHAKE_16_256",
                     "XMSS-SHAKE_20_256 (sizes only; keygen exceeds 240 s)"],
            "SLH-DSA": [
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
                "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
                "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
                "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
                "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
                "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
            ],
        },
        "throughput_ms_median": r["throughput"],
        "peak_rss_kb": r["memory_kb"],
        "sizes_verified": {k: v["match"] for k, v in r["sizes_verified"].items()},
        "state": r["state"],
        "exhaustion": r["exhaustion"],
        "adversarial_cases": {alg: len(c) for alg, c in r["adversarial"].items()},
        "cross_implementation_all_pass": all(
            all(v for v in cases.values())
            for cases in r["cross_implementation"].values()),
        "determinism": r["determinism"],
        "artifact_size_impact": r["artifact_size_impact"],
        "environment": r["environment"],
        "weakness": {
            "id": "F-01",
            "title": "stateful private-key state not persisted atomically after signing, so a crash or backup restore reuses the same one-time signature index",
            "reproduced": "REPRODUCED" in before,
            "regression_test_passed": int(m.group(1)) if m else 0,
            "regression_test_failed": int(m.group(2)) if m else -1,
            "remediation": "remediation/state_journal.py — atomic state commit before signature release (write temp + fsync + rename + dir fsync) plus a monotonic journal that refuses stale state with STATE_ROLLBACK; patch in remediation/remediation.patch",
        },
        "findings_total": total,
        "findings_by_severity": counts,
    }
    with open(os.path.join(PACK, "evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"evidence.json written: {total} findings {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
