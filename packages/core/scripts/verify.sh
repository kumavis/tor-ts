#!/usr/bin/env bash
# Verify everything in `packages/core`:
#   1. Build (or reuse) the Thales transpiler at the pinned revision.
#   2. Transpile every TypeScript file under `src/` (recursively) to a
#      Lean sidecar in `Generated/`. Any subset violation aborts here.
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
#                 in lakefile.lean. Update both together. The script
#                 always re-checks out the requested revision before
#                 building, so changing THALES_REV between runs forces
#                 a rebuild rather than silently reusing the previous
#                 binary.
#
# Requirements: `git`, `lake`/`lean` on PATH (install via elan).

set -euo pipefail

PKG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep this SHA in sync with `require thales` in lakefile.lean.
THALES_REV="${THALES_REV:-31f300449ea4514e1975fa559011d18793ee1a7a}"
THALES_REPO="${THALES_REPO:-${PKG_DIR}/.thales}"
THALES_BIN="${THALES_REPO}/.lake/build/bin/thales"

if ! command -v lake >/dev/null 2>&1; then
  echo "error: lake not on PATH. Install elan and the toolchain pinned in lean-toolchain." >&2
  exit 1
fi

# 1. Ensure the Thales repo exists and is checked out at THALES_REV. If the
#    repo is missing, the requested revision is missing, or the current
#    HEAD doesn't match THALES_REV, (re)checkout and rebuild. This stops
#    a stale binary from a previous run silently servicing a new
#    THALES_REV value.
if [[ ! -d "${THALES_REPO}" ]]; then
  echo "==> Cloning Thales into ${THALES_REPO}"
  git clone https://github.com/jessealama/thales.git "${THALES_REPO}"
fi

current_rev="$(git -C "${THALES_REPO}" rev-parse HEAD 2>/dev/null || echo "")"
target_rev="${THALES_REV}"
# Resolve THALES_REV to a SHA so we can compare even if the user passed a
# branch name or short ref.
if git -C "${THALES_REPO}" cat-file -e "${THALES_REV}^{commit}" 2>/dev/null; then
  target_rev="$(git -C "${THALES_REPO}" rev-parse "${THALES_REV}^{commit}")"
else
  echo "==> Fetching Thales (don't know about ${THALES_REV} yet)"
  git -C "${THALES_REPO}" fetch --tags origin
  target_rev="$(git -C "${THALES_REPO}" rev-parse "${THALES_REV}^{commit}")"
fi

if [[ "${current_rev}" != "${target_rev}" ]]; then
  echo "==> Checking out Thales @ ${THALES_REV} (was ${current_rev:0:8}, now ${target_rev:0:8})"
  git -C "${THALES_REPO}" checkout "${target_rev}"
  # Force a rebuild: the existing binary, if any, was for a different rev.
  rm -f "${THALES_BIN}"
fi

if [[ ! -x "${THALES_BIN}" ]]; then
  echo "==> Building Thales"
  (cd "${THALES_REPO}" && lake build thales)
fi

# 2. Transpile every TypeScript file under src/ (recursively) to
#    Generated/*.lean. Clean Generated/ first so renames or deletions in
#    src/ don't leave stale sidecars that would still satisfy `lake build`.
echo "==> Cleaning Generated/"
mkdir -p "${PKG_DIR}/Generated"
find "${PKG_DIR}/Generated" -maxdepth 1 -name '*.lean' -delete

shopt -s nullglob globstar
ts_files=( "${PKG_DIR}/src/"**/*.ts )
if (( ${#ts_files[@]} == 0 )); then
  echo "warning: no .ts files under ${PKG_DIR}/src/"
fi
for ts in "${ts_files[@]}"; do
  echo "==> thales ${ts#${PKG_DIR}/}"
  "${THALES_BIN}" --overwrite -o "${PKG_DIR}/Generated" "${ts}"
done

# 3. Lake build picks up Thales as a `require` and builds Generated/ + Spec/.
echo "==> lake build"
(cd "${PKG_DIR}" && lake build)
