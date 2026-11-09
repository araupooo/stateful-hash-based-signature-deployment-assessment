#!/usr/bin/env bash
# Verify the SHA-256 digests of every shippable pack file.
# Run from the pack root:  bash scripts/verify_digests.sh
set -euo pipefail
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS
