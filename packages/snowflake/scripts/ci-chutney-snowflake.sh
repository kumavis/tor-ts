#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

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

if ! command -v go >/dev/null; then
  echo "go is required"
  exit 1
fi

mkdir -p "${ROOT_DIR}/.bin"
GOBIN="${ROOT_DIR}/.bin" go install gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/server@v2.15.2

export CHUTNEY_DIR="${CHUTNEY_DIR:-/tmp/chutney}"
if [ "${CHUTNEY_SKIP_INSTALL:-0}" != "1" ]; then
  bash "${ROOT_DIR}/packages/tor/scripts/ci-chutney-install.sh"
fi
if [ ! -d "${CHUTNEY_DIR}" ]; then
  echo "Chutney directory missing: ${CHUTNEY_DIR}"
  exit 1
fi
if [ -x "${CHUTNEY_DIR}/.venv/bin/python" ]; then
  export PYTHON="${CHUTNEY_DIR}/.venv/bin/python"
fi
tor --version

export CHUTNEY_DATA_DIR="${CHUTNEY_DATA_DIR:-$(mktemp -d)}"
export CHUTNEY_LISTEN_ADDRESS="${CHUTNEY_LISTEN_ADDRESS:-127.0.0.1}"
export CHUTNEY_DISABLE_IPV6="${CHUTNEY_DISABLE_IPV6:-1}"
export CHUTNEY_DNS_CONF="${CHUTNEY_DNS_CONF:-/dev/null}"
export TOR_TS_TEST_PORT="${TOR_TS_TEST_PORT:-4747}"

cleanup() {
  cd "${CHUTNEY_DIR}" || exit 0
  timeout 2m ./chutney stop || true
  if [ -n "${CHUTNEY_DATA_DIR:-}" ] && [ -d "${CHUTNEY_DATA_DIR}" ]; then
    pkill -f "${CHUTNEY_DATA_DIR}/nodes" || true
    pkill -9 -f "${CHUTNEY_DATA_DIR}/nodes" || true
  fi
}
trap cleanup EXIT

cd "${CHUTNEY_DIR}"

CHUTNEY_NETWORK="${CHUTNEY_NETWORK:-tor-ts-basic-min-snowflake}"

export TOR_TS_SNOWFLAKE_RELAY_URL="${TOR_TS_SNOWFLAKE_RELAY_URL:-ws://127.0.0.1:9900/}"

cat > "networks/${CHUTNEY_NETWORK}" <<EOF
Authority = Node(tag="a", authority=1, relay=1)

# Relay that also runs the snowflake server transport plugin.
# A real bridge stays out of the consensus, matching the browser mainnet path.
SnowflakeRelay = Node(tag="b", bridge=1, relay=1, launch_phase=2, extra_raw_torrc="""\
Sandbox 0
ExitRelay 0
ExtORPort auto
ServerTransportListenAddr snowflake 127.0.0.1:9900
ServerTransportPlugin snowflake exec ${ROOT_DIR}/.bin/server --disable-tls --unsafe-logging --log ${CHUTNEY_DATA_DIR}/nodes/004b/snowflake-server.log
""")

ExitRelay = Node(tag="r", relay=1, exit=1, extra_raw_torrc="""\
ClientRejectInternalAddresses 0
ClientDNSRejectInternalAddresses 0
""")

Client = Node(tag="c", client=1)
Relay = Node(tag="m", relay=1)
HiddenService = Node(tag="h", hs=1, launch_phase=2)
# A bridge client lets Chutney verify bootstrap and descriptor delivery for
# the bridge without introducing another advertised authority into client paths.
BridgeClient = Node(tag="bc", client=1, bridgeclient=1, launch_phase=2)

NODES = Authority.getN(4) + SnowflakeRelay.getN(1) + Relay.getN(3) + ExitRelay.getN(1) + Client.getN(1) + HiddenService.getN(1) + BridgeClient.getN(1)
ConfigureNodes(NODES)
EOF

# `chutney bootstrap` has no built-in retry, and on a 4-authority network
# it's not unusual for one authority's tor process to hang at "starting"
# — the other 3 reach 100% but the 4th never publishes its descriptor in
# time, so the bootstrap fails after chutney's internal 300 s deadline.
# The regular `chutney` job avoids this by running `tools/test-network.sh
# --allow-failures 2`. We do the equivalent here as an explicit retry
# loop, with full teardown between attempts so a stuck tor process
# doesn't poison the next attempt's port allocations.
BOOTSTRAP_ATTEMPTS=3
bootstrap_succeeded=0
for attempt in $(seq 1 ${BOOTSTRAP_ATTEMPTS}); do
  echo ""
  echo "=== chutney bootstrap attempt ${attempt}/${BOOTSTRAP_ATTEMPTS} ==="
  if ./chutney init --net "${CHUTNEY_NETWORK}" && timeout 10m ./chutney bootstrap; then
    bootstrap_succeeded=1
    break
  fi
  echo "Bootstrap attempt ${attempt} failed."
  if [ "${attempt}" -lt "${BOOTSTRAP_ATTEMPTS}" ]; then
    echo "Tearing down before retry..."
    timeout 2m ./chutney stop || true
    if [ -n "${CHUTNEY_DATA_DIR:-}" ] && [ -d "${CHUTNEY_DATA_DIR}" ]; then
      pkill -f "${CHUTNEY_DATA_DIR}/nodes" || true
      pkill -9 -f "${CHUTNEY_DATA_DIR}/nodes" || true
    fi
    sleep 5
  fi
done
if [ "${bootstrap_succeeded}" -ne 1 ]; then
  echo "Bootstrap failed after ${BOOTSTRAP_ATTEMPTS} attempts; aborting."
  exit 1
fi
./chutney status

TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX="$(awk '{print $2}' "${CHUTNEY_DATA_DIR}"/nodes/*r/fingerprint | head -n 1 | tr 'A-Z' 'a-z')"
export TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX

echo ""
echo "=== chutney snowflake torrc summary (debug) ==="
echo "CHUTNEY_DATA_DIR=${CHUTNEY_DATA_DIR}"
echo "TOR_TS_TEST_PORT=${TOR_TS_TEST_PORT}"
echo "TOR_TS_SNOWFLAKE_RELAY_URL=${TOR_TS_SNOWFLAKE_RELAY_URL}"
echo "TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX}"
echo ""
for torrc in "${CHUTNEY_DATA_DIR}"/nodes/*/torrc; do
  echo "--- ${torrc}"
  grep -nE "^(SocksPort|ORPort|DirPort|BridgeRelay|ExtORPort|ServerTransportListenAddr|ServerTransportPlugin|ExitPolicyRejectLocalInterfaces|ExitPolicyRejectPrivate|ExitPolicy|ClientRejectInternalAddresses|ClientDNSRejectInternalAddresses)\\b" "${torrc}" || true
done
echo "=== end torrc summary ==="
echo ""

cd "${ROOT_DIR}"
timeout 3m node --experimental-transform-types "${ROOT_DIR}/packages/snowflake/scripts/chutney-snowflake-ci.ts"

# Exercise the actual browser factory (JS TLS + shared Snowflake channel + HS),
# rather than inferring onion support from the Node exit-only test above.
export CHUTNEY_PATH="${CHUTNEY_DIR}"
export TOR_TS_HS_HOSTNAME_PATH="${CHUTNEY_DATA_DIR}/hs_hostname.txt"
"${CHUTNEY_DIR}/tools/hsaddress.sh" | head -n 1 | sed 's/^Node [^:]*: //' > "${TOR_TS_HS_HOSTNAME_PATH}"
timeout 6m yarn workspace browser test:chutney
