#!/usr/bin/env python3
"""Journaled stateful signer — the remediation for F-01.

A stateful (LMS/XMSS) private key is usable only while its one-time
signature index advances monotonically. The index lives inside the
serialized secret key, so the key file IS the state. A signer that
releases a signature and only afterwards persists the updated key
file loses the index advance on any crash, power loss, or backup
restore between the two steps — and the next signature reuses the
same one-time key (see reproduce_weakness.py).

This module fixes the ordering and adds rollback detection:

1. Atomic commit before release. The updated serialized secret key
   is written to a temporary file in the same directory, fsynced,
   atomically renamed over the state file, and the directory is
   fsynced — BEFORE the signature is returned to the caller. A crash
   anywhere before the commit means no signature was released, so
   reusing the same index afterwards is safe; a crash after the
   commit means the index already advanced.
2. Monotonic journal. journal.json records the key id and the last
   index a signature was released for. On load, if the journal's last
   committed index is >= the index the loaded state would use next,
   the state file is stale (restored from an older backup, or the
   commit was lost) and signing is refused with STATE_ROLLBACK
   instead of silently reusing the index.
3. The liboqs driver itself refuses to sign without a secure-store
   callback, and wipes the signature if the store fails
   (sig_stfl_lms_functions.c); the journal is the application-level
   half of that contract — the callback captures the new state, and
   this module is what persists it atomically before release.

State directory layout:
  state.bin    serialized secret key (liboqs format, hex in the driver)
  public.bin   public key (hex), written at keygen
  journal.json {"key_id": ..., "last_committed_index": int, "released": int}

Only the stateful driver (src/stfl_driver) is used for cryptography;
this module only moves bytes and enforces ordering.
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
DEFAULT_DRIVER = os.path.join(PACK, "src", "stfl_driver")


class SignerError(Exception):
    """Refusal to sign, with a machine-readable reason."""


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path, data: bytes):
    """Write data to path atomically: temp file + fsync + rename + dir fsync."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path) or ".")


def _key_id(public_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


class JournaledSigner:
    def __init__(self, state_dir, driver=DEFAULT_DRIVER, alg="LMS_SHA256_H10_W4"):
        self.state_dir = state_dir
        self.driver = driver
        self.alg = alg

    # -- driver plumbing -------------------------------------------------
    def _run(self, *args):
        r = subprocess.run([self.driver] + list(args), capture_output=True, text=True)
        if r.returncode != 0:
            raise SignerError(f"driver {' '.join(args[:2])} failed: {r.stdout.strip()} {r.stderr.strip()}")
        return dict(l.split(None, 1) for l in r.stdout.splitlines() if " " in l)

    # -- key management --------------------------------------------------
    def keygen(self):
        os.makedirs(self.state_dir, exist_ok=True)
        d = self._run("keygen", self.alg)
        _atomic_write(os.path.join(self.state_dir, "state.bin"),
                      d["secret_key"].encode())
        _atomic_write(os.path.join(self.state_dir, "public.bin"),
                      d["public_key"].encode())
        journal = {"key_id": _key_id(d["public_key"]),
                   "last_committed_index": -1, "released": 0}
        _atomic_write(os.path.join(self.state_dir, "journal.json"),
                      json.dumps(journal, indent=2).encode())
        return d["public_key"]

    def _load_journal(self):
        p = os.path.join(self.state_dir, "journal.json")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def _next_index(self, secret_key_hex):
        d = self._run("remaining", self.alg, secret_key_hex)
        total = int(d["sigs_total"])
        remaining = int(d["sigs_remaining"])
        return total - remaining, total, remaining

    # -- signing ---------------------------------------------------------
    def sign(self, message: bytes):
        """Sign message; commit the new state atomically BEFORE returning
        the signature. Raises SignerError(STATE_ROLLBACK) on stale state."""
        state_path = os.path.join(self.state_dir, "state.bin")
        with open(state_path) as f:
            sk_hex = f.read().strip()
        with open(os.path.join(self.state_dir, "public.bin")) as f:
            pk_hex = f.read().strip()
        next_index, total, _ = self._next_index(sk_hex)
        journal = self._load_journal()
        if journal is not None:
            if journal["key_id"] != _key_id(pk_hex):
                raise SignerError("KEY_MISMATCH: journal belongs to a different key")
            if journal["last_committed_index"] >= next_index:
                raise SignerError(
                    f"STATE_ROLLBACK: journal last_committed_index="
                    f"{journal['last_committed_index']} but loaded state would "
                    f"reuse index {next_index} (state file is stale)")
        d = self._run("sign", self.alg, sk_hex, message.hex())
        index = int(d["signature_index"])
        if index != next_index:
            raise SignerError(f"INDEX_MISMATCH: driver used index {index}, expected {next_index}")
        # Commit BEFORE release: state first, then journal.
        _atomic_write(state_path, d["secret_key"].encode())
        new_journal = {"key_id": _key_id(pk_hex),
                       "last_committed_index": index,
                       "released": (journal["released"] if journal else 0) + 1}
        _atomic_write(os.path.join(self.state_dir, "journal.json"),
                      json.dumps(new_journal, indent=2).encode())
        return {"signature": d["signature"], "index": index,
                "public_key": pk_hex}

    def verify(self, public_key_hex, message: bytes, signature_hex):
        d = self._run("verify", self.alg, public_key_hex, message.hex(), signature_hex)
        return d.get("verify") == "VALID"


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--driver", default=DEFAULT_DRIVER)
    ap.add_argument("--alg", default="LMS_SHA256_H10_W4")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sp = sub.add_parser("sign")
    sp.add_argument("--message", required=True)
    a = ap.parse_args(argv)
    s = JournaledSigner(a.state_dir, driver=a.driver, alg=a.alg)
    if a.cmd == "keygen":
        print("public_key", s.keygen())
    else:
        r = s.sign(a.message.encode())
        print(f"signature_index {r['index']}")
        print(f"signature {r['signature']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
