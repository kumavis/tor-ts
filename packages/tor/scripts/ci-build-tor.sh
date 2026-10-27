#!/usr/bin/env bash
set -euo pipefail

# The INTRODUCE1 490-byte limit is enforced starting in 0.4.9.9. Distribution
# packages can lag behind that behavior, so both Chutney jobs use this exact
# stable release. Keep the commit check even when fetching by tag.
TOR_TAG=tor-0.4.9.14
TOR_COMMIT=8fe2745aee2c35116ff1081f19b2952418b43069
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD_ROOT="${TOR_BUILD_ROOT:-${ROOT_DIR}/.ci-tor}"
INSTALL_DIR="${BUILD_ROOT}/install"

if [ ! -f "${INSTALL_DIR}/revision" ] || [ "$(cat "${INSTALL_DIR}/revision")" != "${TOR_COMMIT}" ]; then
  mkdir -p "${BUILD_ROOT}"
  if [ ! -d "${BUILD_ROOT}/src/.git" ]; then
    git clone --depth 1 --branch "${TOR_TAG}" \
      https://gitlab.torproject.org/tpo/core/tor.git "${BUILD_ROOT}/src"
  fi
  test "$(git -C "${BUILD_ROOT}/src" rev-parse HEAD)" = "${TOR_COMMIT}"
  (
    cd "${BUILD_ROOT}/src"
    ./autogen.sh
    # Optional arguments let local runs locate non-system OpenSSL/libevent.
    ./configure --disable-asciidoc --disable-manpage --disable-html-manual "$@"
    make -j"${TOR_BUILD_JOBS:-2}" src/app/tor src/tools/tor-gencert
  )
  mkdir -p "${INSTALL_DIR}/bin"
  install -m 755 "${BUILD_ROOT}/src/src/app/tor" "${INSTALL_DIR}/bin/tor"
  install -m 755 "${BUILD_ROOT}/src/src/tools/tor-gencert" "${INSTALL_DIR}/bin/tor-gencert"
  echo "${TOR_COMMIT}" > "${INSTALL_DIR}/revision"
fi

"${INSTALL_DIR}/bin/tor" --version
# Preserve executable modes when sharing the build with the two test jobs.
tar -czf "${BUILD_ROOT}/tor-bin.tar.gz" -C "${INSTALL_DIR}" bin revision
