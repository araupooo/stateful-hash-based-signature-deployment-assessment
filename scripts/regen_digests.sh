#!/usr/bin/env bash
# Regenerate SHA256SUMS over every file that ships in the repository.
# Excluded (stated in README.md): docs/index.html (generated page, its own
# digest row would be self-referential), submission-text-final.txt (a
# submission draft, not pack content), PACK-READY.md (a working note, not
# pack content), the liboqs source/build trees, the extracted
# reference-implementation trees (rebuilt/extracted by
# run_all.sh from the bundled tarballs) and the compiled drivers (build
# artefacts, rebuilt by run_all.sh), the venv, .git, and SHA256SUMS itself.
set -euo pipefail
cd "$(dirname "$0")/.."
find . -type f \
  -not -path './.git/*' \
  -not -path './venv/*' \
  -not -path './src/liboqs-0.16.0/*' \
  -not -path './src/liboqs-build/*' \
  -not -path './src/hash-sigs/*' \
  -not -path './src/xmss-reference/*' \
  -not -path '*/__pycache__/*' \
  -not -path './docs/index.html' \
  ! -name SHA256SUMS \
  ! -name pq_driver \
  ! -name stfl_driver \
  ! -name ref_lms \
  ! -name ref_xmss \
  ! -name submission-text-final.txt \
  ! -name PACK-READY.md \
  -exec sha256sum {} + | sort -k2 > SHA256SUMS
echo "SHA256SUMS regenerated: $(wc -l < SHA256SUMS) files"
