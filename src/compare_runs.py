#!/usr/bin/env python3
"""Compare two runs deterministically (see README.md, comparison rule).

Usage: python3 src/compare_runs.py outputs/run1 outputs/run2-clean

Compared (must be equal):
  * sizes_verified match flags (all parameter sets, both/all
    implementations)
  * state fields: serialized secret-key sizes, total/remaining
    signature counts, expected totals (deterministic per set)
  * every adversarial outcome string
  * every cross-implementation boolean
  * determinism booleans and leaf indices (same state, same message)
  * state-exhaustion outcomes (sign-all ok, sign-after-exhaustion fails)
  * remediation verdicts: "REPRODUCED" in remediation-before.log and the
    regression-test pass line in remediation-after.log
Checked but NOT asserted equal (reported only):
  * timing medians and peak-RSS values (vary between runs by design)
  * digests of freshly generated keys/signatures (keys are fresh per run)

Exit code 0 and a final "MATCH" line only if every compared field is equal.
"""
import json
import os
import sys


def load(d):
    with open(os.path.join(d, "results.json")) as f:
        return json.load(f)


def main():
    run1_dir, run2_dir = sys.argv[1], sys.argv[2]
    r1, r2 = load(run1_dir), load(run2_dir)
    diffs = []
    checks = 0

    def eq(name, a, b):
        nonlocal checks
        checks += 1
        if a != b:
            diffs.append(f"{name}: run1={a!r} run2={b!r}")
            print(f"DIFF {name}: run1={a!r} run2={b!r}")
        else:
            print(f"PASS {name}")

    for alg, v in r1["sizes_verified"].items():
        eq(f"sizes.{alg}.match", v["match"], r2["sizes_verified"][alg]["match"])
        for refkey in ("hash-sigs_match", "xmss-reference_match"):
            if refkey in v:
                eq(f"sizes.{alg}.{refkey}", v[refkey], r2["sizes_verified"][alg][refkey])
    for alg, v in r1["state"].items():
        for k, val in v.items():
            if k == "not_measured":
                continue
            eq(f"state.{alg}.{k}", val, r2["state"][alg][k])
    for k, v in r1["exhaustion"].items():
        eq(f"exhaustion.{k}", v, r2["exhaustion"][k])
    for alg, cases in r1["adversarial"].items():
        for k, v in cases.items():
            eq(f"adversarial.{alg}.{k}", v, r2["adversarial"][alg][k])
    for alg, cases in r1["cross_implementation"].items():
        for k, v in cases.items():
            eq(f"cross.{alg}.{k}", v, r2["cross_implementation"][alg][k])
    for alg, vals in r1["determinism"].items():
        for k, v in vals.items():
            if "sha256" in k:
                print(f"SKIP {alg}.{k} (fresh keys per run; digest differs by design)")
                continue
            eq(f"determinism.{alg}.{k}", v, r2["determinism"][alg][k])

    for alg, entry in r1["artifact_size_impact"].items():
        for k, v in entry.items():
            eq(f"artifact.{alg}.{k}", v, r2["artifact_size_impact"][alg][k])
    for k, v in r1["environment"].items():
        eq(f"environment.{k}", v, r2["environment"][k])

    # Timing / memory: present and positive in both runs, not asserted equal.
    for alg, impls in r1["throughput"].items():
        for impl, t in impls.items():
            for k, v in t.items():
                if k in ("n", "roundtrip_ok", "verify_ok"):
                    continue
                v2 = r2["throughput"][alg][impl][k]
                ok = isinstance(v, (int, float)) and v > 0 and isinstance(v2, (int, float)) and v2 > 0
                checks += 1
                if ok:
                    print(f"PASS timing-present {alg}.{impl}.{k} run1={v} run2={v2} (values differ by design)")
                else:
                    diffs.append(f"timing {alg}.{impl}.{k}: {v} vs {v2}")
                    print(f"DIFF timing {alg}.{impl}.{k}: run1={v} run2={v2}")
    for alg, impls in r1["memory_kb"].items():
        for impl, v in impls.items():
            v2 = r2["memory_kb"][alg][impl]
            checks += 1
            if v > 0 and v2 > 0:
                print(f"PASS memory-present {alg}.{impl} run1={v}KB run2={v2}KB (values differ by design)")
            else:
                diffs.append(f"memory {alg}.{impl}: {v} vs {v2}")

    # Remediation verdicts.
    for label, fname, needle in [
            ("remediation-before", "remediation-before.log", "REPRODUCED"),
            ("remediation-after", "remediation-after.log", "0 failed")]:
        for run_dir in (run1_dir, run2_dir):
            p = os.path.join(run_dir, fname)
            with open(p) as f:
                content = f.read()
            eq(f"{label}.{os.path.basename(run_dir)}.contains-{needle!r}",
               needle in content, True)

    print(f"--- comparison: {checks} checks, {len(diffs)} differences ---")
    if diffs:
        print("DIFF")
        return 1
    print("MATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
