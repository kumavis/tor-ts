#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v git >/dev/null; then
  echo "git is required"
  exit 1
fi

if ! command -v python3 >/dev/null; then
  echo "python3 is required"
  exit 1
fi

if ! command -v tor >/dev/null; then
  echo "tor is required (apt-get install tor)"
  exit 1
fi

if ! command -v tor-gencert >/dev/null; then
  echo "tor-gencert is required (usually provided by the tor package)"
  exit 1
fi

if ! command -v timeout >/dev/null; then
  echo "timeout is required (coreutils)"
  exit 1
fi

# https://gitlab.torproject.org/tpo/core/chutney
CHUTNEY_REPO_URL="https://gitlab.torproject.org/tpo/core/chutney.git"
CHUTNEY_COMMIT="fb0bff1ffad593314a2692aa0f1d65db6f0251c9"

CHUTNEY_DIR="${CHUTNEY_DIR:-/tmp/chutney}"
rm -rf "${CHUTNEY_DIR}"
git clone "${CHUTNEY_REPO_URL}" "${CHUTNEY_DIR}"
git -C "${CHUTNEY_DIR}" checkout "${CHUTNEY_COMMIT}"

# Patch chutney's torrc template to make localhost exits work reliably in CI.
# (We keep the repo pinned above; this is an in-place CI-only patch.)
python3 - <<'PY'
from pathlib import Path

torrc_py = Path("/tmp/chutney/lib/chutney/tor/torrc.py")
txt = torrc_py.read_text()

needle = """\
            # Each IPv4 tor instance is configured with Address 127.0.0.1 by default
            ExitPolicy accept 127.0.0.0/8:*

            # If you only want tor to connect to localhost, disable these lines:
            # This may cause network failures in some circumstances
            ExitPolicyRejectPrivate 0
            ExitPolicy accept private:*
"""

replacement = """\
            # Each IPv4 tor instance is configured with Address 127.0.0.1 by default
            # Allow connecting to localhost and local interfaces in CI-only networks.
            ExitPolicyRejectLocalInterfaces 0
            ExitPolicyRejectPrivate 0
            ExitPolicy accept 127.0.0.0/8:*

            # If you only want tor to connect to localhost, disable these lines:
            # This may cause network failures in some circumstances
            ExitPolicy accept private:*
"""

if needle not in txt:
    raise SystemExit("Unexpected chutney torrc template; cannot apply CI patch safely.")

txt = txt.replace(needle, replacement)
torrc_py.write_text(txt)
print("patched", torrc_py)
PY

# Install chutney deps (declared in pyproject.toml) into user site-packages
python3 -m pip install --user --upgrade pip
python3 -m pip install --user -e "${CHUTNEY_DIR}"

export CHUTNEY_DATA_DIR="${CHUTNEY_DATA_DIR:-$(mktemp -d)}"
export CHUTNEY_LISTEN_ADDRESS="${CHUTNEY_LISTEN_ADDRESS:-127.0.0.1}"
export CHUTNEY_DISABLE_IPV6="${CHUTNEY_DISABLE_IPV6:-1}"
export CHUTNEY_DNS_CONF="${CHUTNEY_DNS_CONF:-/dev/null}"
export TOR_TS_TEST_PORT="${TOR_TS_TEST_PORT:-4747}"
export TOR_TS_HS_TARGET_PORT="${TOR_TS_HS_TARGET_PORT:-4748}"

cleanup() {
  cd "${CHUTNEY_DIR}" || exit 0
  timeout 2m ./chutney stop "${CHUTNEY_NETWORK}" || true
  # If chutney can't stop cleanly, forcibly kill remaining tor instances.
  if [ -n "${CHUTNEY_DATA_DIR:-}" ] && [ -d "${CHUTNEY_DATA_DIR}" ]; then
    pkill -f "${CHUTNEY_DATA_DIR}/nodes" || true
    pkill -9 -f "${CHUTNEY_DATA_DIR}/nodes" || true
  fi
}
trap cleanup EXIT

cd "${CHUTNEY_DIR}"

# Create a CI-only network config that allows exiting to localhost.
# This avoids REASON_EXITPOLICY when testing e2e against a local HTTP server.
CHUTNEY_NETWORK="${CHUTNEY_NETWORK:-tor-ts-basic-min}"
mkdir -p "${CHUTNEY_DATA_DIR}/hs_service"
export TOR_TS_HS_HOSTNAME_PATH="${CHUTNEY_DATA_DIR}/hs_service/hostname"

cat > "networks/${CHUTNEY_NETWORK}" <<EOF
Authority = Node(tag="a", authority=1, relay=1)

# Extra relays to make HS intro/rend + descriptor upload circuits viable.
Relay = Node(tag="m", relay=1)

# Allow exiting to localhost for CI-only integration tests.
ExitRelay = Node(tag="r", relay=1, exit=1, extra_raw_torrc="""\
ClientRejectInternalAddresses 0
ClientDNSRejectInternalAddresses 0
""")

Client = Node(tag="c", client=1)

HiddenService = Node(tag="h", client=1, extra_raw_torrc="""\
EnforceDistinctSubnets 0
UseEntryGuards 0
HiddenServiceDir ${CHUTNEY_DATA_DIR}/hs_service
HiddenServicePort 80 127.0.0.1:${TOR_TS_HS_TARGET_PORT}
""")

NODES = Authority.getN(4) + Relay.getN(6) + ExitRelay.getN(1) + Client.getN(1) + HiddenService.getN(1)
ConfigureNodes(NODES)
EOF

timeout 10m ./chutney bootstrap "${CHUTNEY_NETWORK}"
./chutney status "${CHUTNEY_NETWORK}"

# Force the integration test to use the real exit relay.
# Chutney writes a hex fingerprint in nodes/*r/fingerprint; that's the SHA1 digest we use.
TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX="$(awk '{print $2}' "${CHUTNEY_DATA_DIR}"/nodes/*r/fingerprint | head -n 1 | tr 'A-Z' 'a-z')"
export TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX

# Dump relevant torrc lines for debugging exit-policy failures
echo ""
echo "=== chutney torrc summary (debug) ==="
echo "CHUTNEY_DATA_DIR=${CHUTNEY_DATA_DIR}"
echo "TOR_TS_TEST_PORT=${TOR_TS_TEST_PORT}"
echo "TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX}"
echo "TOR_TS_HS_TARGET_PORT=${TOR_TS_HS_TARGET_PORT}"
echo "TOR_TS_HS_HOSTNAME_PATH=${TOR_TS_HS_HOSTNAME_PATH}"
echo ""
for torrc in "${CHUTNEY_DATA_DIR}"/nodes/*/torrc; do
  echo "--- ${torrc}"
  grep -nE "^(SocksPort|ORPort|DirPort|ExitRelay|ExitPolicy|ExitPolicyRejectLocalInterfaces|ExitPolicyRejectPrivate|ClientRejectInternalAddresses|ClientDNSRejectInternalAddresses|ReducedExitPolicy)\\b" "${torrc}" || true
done
echo "=== end torrc summary ==="
echo ""

cd "${ROOT_DIR}"

TOR_TS_CHUTNEY_TESTS="${TOR_TS_CHUTNEY_TESTS:-exit,hidden-service}"
IFS=',' read -ra TESTS <<< "${TOR_TS_CHUTNEY_TESTS}"
for t in "${TESTS[@]}"; do
  case "${t}" in
    exit)
      echo ""
      echo "=== running chutney integration test: exit ==="
      timeout 2m node --experimental-transform-types "${ROOT_DIR}/scripts/chutney-ci.ts"
      ;;
    hidden-service)
      echo ""
      echo "=== running chutney integration test: hidden-service ==="
      timeout 10m node --experimental-transform-types "${ROOT_DIR}/scripts/chutney-hidden-service-ci.ts"
      ;;
    *)
      echo "Unknown TOR_TS_CHUTNEY_TESTS entry: ${t}"
      exit 1
      ;;
  esac
done

