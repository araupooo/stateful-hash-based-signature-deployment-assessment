#!/usr/bin/env python3
"""Vulnerable stateful signer (BEFORE) — the F-01 failure mode.

Ordering flaw: the signer releases the signature to the caller and
only afterwards persists the updated secret-key state. If the process
crashes, loses power, or is killed between the release and the
persist — or if the state file is later restored from a backup taken
before the signature — the next signature reuses the same one-time
signature index, and both signatures verify under the same public
key. The one-time key is used twice.

  python3 vulnerable_signer.py --state-dir DIR keygen
  python3 vulnerable_signer.py --state-dir DIR sign --message MSG
        [--no-persist]   # --no-persist simulates a crash after release

The fixed caller (vulnerable_signer.fixed.py) uses the journaled
signer from state_journal.py, which commits the new state atomically
before releasing the signature and refuses stale state.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
DEFAULT_DRIVER = os.path.join(PACK, "src", "stfl_driver")


def _run(driver, *args):
    r = subprocess.run([driver] + list(args), capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"driver {' '.join(args[:2])} failed: {r.stdout.strip()} {r.stderr.strip()}")
    return dict(l.split(None, 1) for l in r.stdout.splitlines() if " " in l)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--driver", default=DEFAULT_DRIVER)
    ap.add_argument("--alg", default="LMS_SHA256_H10_W4")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sp = sub.add_parser("sign")
    sp.add_argument("--message", required=True)
    sp.add_argument("--no-persist", action="store_true",
                    help="simulate a crash after release: do not persist the new state")
    a = ap.parse_args(argv)
    os.makedirs(a.state_dir, exist_ok=True)
    state_path = os.path.join(a.state_dir, "state.bin")
    if a.cmd == "keygen":
        d = _run(a.driver, "keygen", a.alg)
        with open(state_path, "w") as f:
            f.write(d["secret_key"])
        with open(os.path.join(a.state_dir, "public.bin"), "w") as f:
            f.write(d["public_key"])
        print("public_key", d["public_key"])
        return 0
    with open(state_path) as f:
        sk_hex = f.read().strip()
    d = _run(a.driver, "sign", a.alg, sk_hex, a.message.encode().hex())
    # VULNERABLE ORDER: the signature is released (printed) BEFORE the
    # updated state is persisted.
    print(f"signature_index {d['signature_index']}")
    print(f"signature {d['signature']}")
    if a.no_persist:
        print("CRASH: process killed before persisting the new state", file=sys.stderr)
        return 0
    with open(state_path, "w") as f:
        f.write(d["secret_key"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
