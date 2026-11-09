#!/usr/bin/env python3
"""Fixed stateful signer (AFTER) — the F-01 remediation, as a
drop-in replacement for vulnerable_signer.py.

Same CLI, but signing goes through the journaled signer
(state_journal.py): the updated state is committed atomically
before the signature is released, and a state file restored from an
older backup is refused with STATE_ROLLBACK instead of silently
reusing a one-time signature index.

  python3 vulnerable_signer.fixed.py --state-dir DIR keygen
  python3 vulnerable_signer.fixed.py --state-dir DIR sign --message MSG
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from state_journal import JournaledSigner, SignerError  # noqa: E402

PACK = os.path.dirname(HERE)
DEFAULT_DRIVER = os.path.join(PACK, "src", "stfl_driver")


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
                    help="accepted for CLI compatibility; the journaled signer "
                         "always commits before release, so this flag has no effect")
    a = ap.parse_args(argv)
    s = JournaledSigner(a.state_dir, driver=a.driver, alg=a.alg)
    if a.cmd == "keygen":
        print("public_key", s.keygen())
        return 0
    try:
        r = s.sign(a.message.encode())
    except SignerError as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 1
    print(f"signature_index {r['index']}")
    print(f"signature {r['signature']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
