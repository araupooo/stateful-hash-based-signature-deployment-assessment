#!/usr/bin/env bash
# Clean reproduction: rebuild everything from a fresh copy of the pack
# (no venv, no build artefacts, no previous outputs) into
# outputs/run2-clean/, then compare the deterministic fields of run1 and
# run2-clean with src/compare_runs.py.
#
# Comparison rule (see README.md): only deterministic fields are compared
# (sizes, round-trip outcomes, adversarial outcomes, cross-implementation
# outcomes, determinism booleans, remediation verdicts). Timing medians
# and peak-RSS values are reported in both runs but are NOT asserted
# equal — they vary between runs by design. Test keys are generated fresh
# per run, so digests of keys/signatures also differ and are excluded.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "fresh copy -> $WORK"
rsync -a --exclude .git --exclude venv \
  --exclude src/liboqs-0.16.0 --exclude src/liboqs-build --exclude src/pq_driver \
  --exclude src/stfl_driver --exclude src/ref_lms --exclude src/ref_xmss \
  --exclude src/hash-sigs --exclude src/xmss-reference \
  --exclude outputs --exclude docs/index.html --exclude SHA256SUMS \
  --exclude submission-text-final.txt ./ "$WORK/pack/"
mkdir -p "$WORK/pack/outputs"
(cd "$WORK/pack" && bash scripts/run_all.sh run2-clean > outputs/run2-clean-build.log 2>&1)
echo "re-run complete; copying outputs/run2-clean back ..."
rm -rf outputs/run2-clean
cp -r "$WORK/pack/outputs/run2-clean" outputs/run2-clean
cp "$WORK/pack/outputs/run2-clean-build.log" outputs/run2-clean-build.log
echo "comparing run1 vs run2-clean ..."
python3 src/compare_runs.py outputs/run1 outputs/run2-clean | tee outputs/run-comparison.log
bash scripts/regen_digests.sh
