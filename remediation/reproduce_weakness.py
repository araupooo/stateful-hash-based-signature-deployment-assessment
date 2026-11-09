#!/usr/bin/env python3
"""Reproduce F-01: stateful private-key state not persisted atomically
after signing, so a crash (or backup restore) reuses the same
one-time signature index.

Steps (all through the vulnerable signer, remediation/vulnerable_signer.py):
  1. Generate an LMS key (H5/W4: 31 signatures total, small and fast).
  2. Sign message A. The signature is released, then the process
     "crashes" before persisting the updated state (--no-persist).
  3. Sign message B. The signer loads the same stale state file, so
     liboqs signs with the same leaf index again.
  4. Both signatures verify under the same public key — the one-time
     signature key at that index was used twice, which is exactly the
     reuse RFC 8554 section 6.2 / SP 800-208 requires never to happen.

Exit code 0 and a final "REPRODUCED" line only if the reuse is
observed: same leaf index for two different messages, both
signatures VALID.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
DRIVER = os.path.join(PACK, "src", "stfl_driver")
VULN = os.path.join(HERE, "vulnerable_signer.py")
ALG = "LMS_SHA256_H5_W4"


def run(*args, expect=0):
    r = subprocess.run([sys.executable] + list(args), capture_output=True, text=True)
    if expect is not None and r.returncode != expect:
        raise SystemExit(f"command failed rc={r.returncode}: {' '.join(args)}\n{r.stdout}\n{r.stderr}")
    return r


def parse(out):
    return dict(l.split(None, 1) for l in out.splitlines() if " " in l)


def main():
    print("=== F-01 reproduction: non-atomic state persist reuses a one-time index ===")
    tmp = tempfile.mkdtemp(prefix="f01-repro-")
    state_dir = os.path.join(tmp, "state")
    try:
        run(VULN, "--state-dir", state_dir, "--driver", DRIVER, "--alg", ALG, "keygen")
        with open(os.path.join(state_dir, "public.bin")) as f:
            pk = f.read().strip()
        msg_a, msg_b = "release-1.0 manifest", "release-1.1 manifest"
        r = run(VULN, "--state-dir", state_dir, "--driver", DRIVER, "--alg", ALG,
                "sign", "--message", msg_a, "--no-persist")
        d_a = parse(r.stdout)
        print(f"sign A: index={d_a['signature_index']} (released, then CRASH before persist)")
        r = run(VULN, "--state-dir", state_dir, "--driver", DRIVER, "--alg", ALG,
                "sign", "--message", msg_b)
        d_b = parse(r.stdout)
        print(f"sign B: index={d_b['signature_index']} (signed from the stale state file)")
        same_index = d_a["signature_index"] == d_b["signature_index"]
        print(f"same leaf index used twice: {same_index}")
        # Both signatures verify under the same public key.
        for label, msg, sig in (("A", msg_a, d_a["signature"]), ("B", msg_b, d_b["signature"])):
            r = subprocess.run([DRIVER, "verify", ALG, pk, msg.encode().hex(), sig],
                               capture_output=True, text=True)
            print(f"verify signature {label}: {r.stdout.strip()}")
            assert "VALID" in r.stdout, r.stdout
        reproduced = same_index
        print("REPRODUCED" if reproduced else "NOT REPRODUCED")
        return 0 if reproduced else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
