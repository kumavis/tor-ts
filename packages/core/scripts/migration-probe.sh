#!/usr/bin/env bash
# Migration probe: run every packages/core/src/*.ts through a *new* Thales
# build and record, per file, whether it still emits and whether the
# emitted Lean still compiles. Does NOT touch the committed pin — it
# writes into a scratch directory so the working tree stays clean.
#
# Usage:
#   THALES_BIN=/tmp/thales-check/.lake/build/bin/thales \
#   bash packages/core/scripts/migration-probe.sh
#
# Output: a per-file PASS/EMIT-FAIL table on stdout, and the full
# diagnostics under $OUT/logs/.

set -uo pipefail

PKG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
THALES_BIN="${THALES_BIN:?set THALES_BIN to the new thales binary}"
OUT="${OUT:-/tmp/core-migration-probe}"

rm -rf "${OUT}"
mkdir -p "${OUT}/emitted" "${OUT}/logs"

echo "=============================================="
echo "Thales emit probe"
echo "  binary: ${THALES_BIN}"
echo "  out:    ${OUT}"
echo "=============================================="
echo

pass=0
fail=0
failed_files=()

shopt -s nullglob
for ts in "${PKG_DIR}/src/"*.ts; do
  name="$(basename "${ts}")"
  log="${OUT}/logs/${name}.log"
  if "${THALES_BIN}" --overwrite -o "${OUT}/emitted" "${ts}" >"${log}" 2>&1; then
    printf '  %-28s EMIT OK\n' "${name}"
    pass=$((pass + 1))
  else
    printf '  %-28s EMIT FAIL\n' "${name}"
    fail=$((fail + 1))
    failed_files+=("${name}")
  fi
done

echo
echo "----------------------------------------------"
echo "emit: ${pass} ok, ${fail} failed"
if (( fail > 0 )); then
  echo
  echo "Failures (first 5 diagnostic lines each):"
  for f in "${failed_files[@]}"; do
    echo
    echo "### ${f}"
    head -5 "${OUT}/logs/${f}.log"
  done
fi
echo "----------------------------------------------"
