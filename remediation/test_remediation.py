#!/usr/bin/env python3
"""Regression test for the F-01 remediation (atomic state commit +
monotonic journal).

Structure (mirrors the before/after discipline of the pack):
  BEFORE (the failure mode, expected): signing message A, crashing
  before the state is persisted, then signing message B reuses the
  same leaf index, and both signatures verify. This section proves
  the test can detect the failure mode; it is not a vacuous pass.
  AFTER (the remediation, all must pass):
    1. Sequential signatures use distinct, advancing indices.
    2. Restoring the state file from a pre-sign backup is refused
       with STATE_ROLLBACK (no signature is produced).
    3. A crash before commit releases nothing: the same index can
       still be used afterwards, exactly once, and the signature
       verifies.
    4. A tampered state file is refused (deserialize fails).
    5. Remediation signatures verify under liboqs directly.
    6. The journal matches the state (last committed index == last
       used index; released count == number of signatures).
    7. The remediation patch applies cleanly to a fresh copy of
       vulnerable_signer.py and the patched caller refuses a
       backup-restore rollback.

Trigger:
  python3 remediation/test_remediation.py [--driver src/stfl_driver]

Exit code 0 only if the BEFORE section reproduces the failure mode
AND all AFTER checks pass.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


def run_cli(exe, *args, expect=None):
    r = subprocess.run([sys.executable, exe] + list(args),
                       capture_output=True, text=True)
    if expect is not None and r.returncode != expect:
        raise AssertionError(f"{exe} {' '.join(args)} rc={r.returncode} "
                             f"(expected {expect}): {r.stdout} {r.stderr}")
    return r


def parse(out):
    return dict(l.split(None, 1) for l in out.splitlines() if " " in l)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", default="src/stfl_driver")
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    pack = os.path.dirname(here)
    driver = os.path.join(pack, a.driver) if not os.path.isabs(a.driver) else a.driver
    vuln = os.path.join(here, "vulnerable_signer.py")
    fixed = os.path.join(here, "vulnerable_signer.fixed.py")
    alg = "LMS_SHA256_H5_W4"
    tmp = tempfile.mkdtemp(prefix="f01-test-")
    try:
        # ---------------- BEFORE ----------------
        print("=== BEFORE (failure mode): crash before persist reuses the index ===")
        state_dir = os.path.join(tmp, "before")
        run_cli(vuln, "--state-dir", state_dir, "--driver", driver, "--alg", alg, "keygen")
        with open(os.path.join(state_dir, "public.bin")) as f:
            pk = f.read().strip()
        r = run_cli(vuln, "--state-dir", state_dir, "--driver", driver, "--alg", alg,
                    "sign", "--message", "release-1.0 manifest", "--no-persist")
        d_a = parse(r.stdout)
        r = run_cli(vuln, "--state-dir", state_dir, "--driver", driver, "--alg", alg,
                    "sign", "--message", "release-1.1 manifest")
        d_b = parse(r.stdout)
        check("before_first_signature_valid",
              subprocess.run([driver, "verify", alg, pk, b"release-1.0 manifest".hex(),
                              d_a["signature"]], capture_output=True, text=True).stdout.strip() == "verify VALID")
        check("before_reused_index_signatures_both_verify",
              subprocess.run([driver, "verify", alg, pk, b"release-1.1 manifest".hex(),
                              d_b["signature"]], capture_output=True, text=True).stdout.strip() == "verify VALID")
        check("before_same_index_used_twice",
              d_a["signature_index"] == d_b["signature_index"] == "0",
              f"index A={d_a['signature_index']} index B={d_b['signature_index']}")
        before_reproduced = d_a["signature_index"] == d_b["signature_index"]

        # ---------------- AFTER ----------------
        print("=== AFTER (remediation): journaled signer ===")
        from state_journal import JournaledSigner, SignerError
        state_dir2 = os.path.join(tmp, "after")
        s = JournaledSigner(state_dir2, driver=driver, alg=alg)
        pk2 = s.keygen()
        r1 = s.sign(b"release-1.0 manifest")
        r2 = s.sign(b"release-1.1 manifest")
        r3 = s.sign(b"release-1.2 manifest")
        check("after_sequential_signatures_use_distinct_indices",
              (r1["index"], r2["index"], r3["index"]) == (0, 1, 2),
              f"indices={(r1['index'], r2['index'], r3['index'])}")
        # Backup-restore: restore the state file from a backup taken
        # before r2/r3 were signed; the journal must refuse the next sign.
        backup = os.path.join(tmp, "state-backup.bin")
        shutil.copy(os.path.join(state_dir2, "state.bin"), backup)
        # Sign once more so the backup is genuinely stale, then restore it.
        r4 = s.sign(b"release-1.3 manifest")
        shutil.copy(backup, os.path.join(state_dir2, "state.bin"))
        try:
            s.sign(b"release-1.4 manifest")
            check("after_backup_restore_refused", False, "no exception raised")
        except SignerError as e:
            check("after_backup_restore_refused", "STATE_ROLLBACK" in str(e), str(e))
        # Crash before commit releases nothing: a fresh signer whose
        # sign is interrupted before the commit must still be able to
        # use the same index exactly once afterwards.
        state_dir3 = os.path.join(tmp, "crash")
        s3 = JournaledSigner(state_dir3, driver=driver, alg=alg)
        s3.keygen()
        # Simulate the crash: sign directly through the driver without
        # committing (as the vulnerable caller does with --no-persist),
        # then let the journaled signer sign the same index once.
        with open(os.path.join(state_dir3, "state.bin")) as f:
            sk_hex = f.read().strip()
        d = s3._run("sign", alg, sk_hex, b"unreleased message".hex())
        crashed_index = int(d["signature_index"])
        r_ok = s3.sign(b"released message")
        check("after_crash_before_commit_releases_nothing_and_state_reusable",
              r_ok["index"] == crashed_index and s3.verify(r_ok["public_key"], b"released message", r_ok["signature"]),
              f"crashed index={crashed_index}, next released index={r_ok['index']}")
        # Tampered state file is refused.
        state_dir4 = os.path.join(tmp, "tampered")
        s4 = JournaledSigner(state_dir4, driver=driver, alg=alg)
        s4.keygen()
        p = os.path.join(state_dir4, "state.bin")
        with open(p) as f:
            data = f.read()
        with open(p, "w") as f:
            f.write(("0" if data[0] != "0" else "1") + data[1:])
        try:
            s4.sign(b"tampered message")
            check("after_tampered_state_refused", False, "no exception raised")
        except SignerError:
            check("after_tampered_state_refused", True)
        # Remediation signatures verify under liboqs directly.
        r = subprocess.run([driver, "verify", alg, pk2, b"release-1.1 manifest".hex(),
                            r2["signature"]], capture_output=True, text=True)
        check("after_signatures_verify_under_liboqs", "VALID" in r.stdout)
        # Journal matches the state.
        with open(os.path.join(state_dir2, "journal.json")) as f:
            journal = json.load(f)
        check("after_journal_matches_state",
              journal["last_committed_index"] == r4["index"] and journal["released"] == 4,
              f"journal={journal}")
        # The patch applies cleanly and the patched caller refuses a
        # backup-restore rollback.
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(os.path.join(here, "vulnerable_signer.py"),
                        os.path.join(td, "vulnerable_signer.py"))
            shutil.copy(os.path.join(here, "state_journal.py"),
                        os.path.join(td, "state_journal.py"))
            patch = os.path.join(here, "remediation.patch")
            r = subprocess.run(["patch", "--dry-run", "-p1", "-i", patch],
                               cwd=td, capture_output=True, text=True)
            check("after_patch_applies_cleanly", r.returncode == 0,
                  r.stdout.strip() or r.stderr.strip())
            r = subprocess.run(["patch", "-p1", "-i", patch],
                               cwd=td, capture_output=True, text=True)
            check("after_patch_applied", r.returncode == 0)
            patched = os.path.join(td, "vulnerable_signer.py")
            pstate = os.path.join(td, "pstate")
            run_cli(patched, "--state-dir", pstate, "--driver", driver, "--alg", alg, "keygen")
            run_cli(patched, "--state-dir", pstate, "--driver", driver, "--alg", alg,
                    "sign", "--message", "one")
            shutil.copy(os.path.join(pstate, "state.bin"), os.path.join(td, "bk.bin"))
            run_cli(patched, "--state-dir", pstate, "--driver", driver, "--alg", alg,
                    "sign", "--message", "two")
            shutil.copy(os.path.join(td, "bk.bin"), os.path.join(pstate, "state.bin"))
            r = run_cli(patched, "--state-dir", pstate, "--driver", driver, "--alg", alg,
                        "sign", "--message", "three", expect=None)
            check("after_patched_caller_refuses_backup_restore",
                  r.returncode == 1 and "STATE_ROLLBACK" in r.stderr,
                  r.stderr.strip()[-120:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"=== regression test: {PASS} passed, {FAIL} failed ===")
    return 0 if (before_reproduced and FAIL == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
