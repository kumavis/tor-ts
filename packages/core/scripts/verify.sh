#!/usr/bin/env bash
# Verify everything in `packages/core`:
#   1. Build (or reuse) the Thales transpiler.
#   2. Transpile every TypeScript file under `src/` to a Lean sidecar in
#      `Generated/`. Any subset violation aborts here.
#   3. Run `lake build` so Lean kernel-checks the generated code together
#      with the hand-written `Spec/` theorems.
#
# Usage:
#   bash packages/core/scripts/verify.sh
#
# Environment:
#   THALES_REPO   Path to a pre-cloned Thales checkout. If unset, the
#                 script clones into `.thales/` next to this package.
#   THALES_REV    Git revision to check out. Defaults to the SHA pinned
#                 in lakefile.lean. Update both together.
#
# Requirements: `git`, `lake`/`lean` on PATH (install via elan).

set -euo pipefail

PKG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep this SHA in sync with `require thales` in lakefile.lean.
THALES_REV="${THALES_REV:-31f300449ea4514e1975fa559011d18793ee1a7a}"
THALES_REPO="${THALES_REPO:-${PKG_DIR}/.thales}"

if ! command -v lake >/dev/null 2>&1; then
  echo "error: lake not on PATH. Install elan and the toolchain pinned in lean-toolchain." >&2
  exit 1
fi

# 1. Build Thales if we don't have it.
if [[ ! -x "${THALES_REPO}/.lake/build/bin/thales" ]]; then
  if [[ ! -d "${THALES_REPO}" ]]; then
    echo "==> Cloning Thales into ${THALES_REPO}"
    git clone https://github.com/jessealama/thales.git "${THALES_REPO}"
  fi
  echo "==> Checking out Thales @ ${THALES_REV}"
  git -C "${THALES_REPO}" fetch --tags origin
  git -C "${THALES_REPO}" checkout "${THALES_REV}"
  echo "==> Building Thales"
  (cd "${THALES_REPO}" && lake build thales)
fi

THALES_BIN="${THALES_REPO}/.lake/build/bin/thales"

# 2. Transpile every src/*.ts to Generated/*.lean.
mkdir -p "${PKG_DIR}/Generated"
shopt -s nullglob
for ts in "${PKG_DIR}/src/"*.ts; do
  echo "==> thales ${ts#${PKG_DIR}/}"
  "${THALES_BIN}" --overwrite -o "${PKG_DIR}/Generated" "${ts}"
done

# 3. Lake build picks up Thales as a `require` and builds Generated/ + Spec/.
echo "==> lake build"
(cd "${PKG_DIR}" && lake build)
