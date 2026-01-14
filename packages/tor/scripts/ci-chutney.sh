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
CHUTNEY_SKIP_INSTALL="${CHUTNEY_SKIP_INSTALL:-0}"

if [ "${CHUTNEY_SKIP_INSTALL}" = "1" ]; then
  if [ ! -d "${CHUTNEY_DIR}" ]; then
    echo "CHUTNEY_SKIP_INSTALL=1 but CHUTNEY_DIR missing: ${CHUTNEY_DIR}"
    exit 1
  fi
else
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
fi

export CHUTNEY_DATA_DIR="${CHUTNEY_DATA_DIR:-$(mktemp -d)}"
export CHUTNEY_LISTEN_ADDRESS="${CHUTNEY_LISTEN_ADDRESS:-127.0.0.1}"
export CHUTNEY_DISABLE_IPV6="${CHUTNEY_DISABLE_IPV6:-1}"
export CHUTNEY_DNS_CONF="${CHUTNEY_DNS_CONF:-/dev/null}"

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

# Chutney's verify test uses port 4747 (LISTEN_PORT in verify.py) for both
# exit relay tests AND hidden service tests. We use the same port for both.
export TOR_TS_TEST_PORT=4747
export TOR_TS_HS_TARGET_PORT=4747

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

# Use Chutney's built-in hs=1 so that 'chutney verify' can test HS connectivity.
# This uses Chutney's managed HS directory and proper timing.
HiddenService = Node(tag="h", hs=1, launch_phase=2)

NODES = Authority.getN(4) + Relay.getN(2) + ExitRelay.getN(1) + Client.getN(1) + HiddenService.getN(1)
ConfigureNodes(NODES)
EOF

timeout 10m ./chutney bootstrap "${CHUTNEY_NETWORK}"
./chutney status "${CHUTNEY_NETWORK}"

# Use Chutney's built-in verify command to test both exit and HS connectivity.
# This has proper timing (waits voting_interval + 10s) and retries, ensuring the
# hidden service descriptor has propagated correctly before we test it.
# The verify command binds a TrafficTester on port 4747 and tests data transmission.
echo ""
echo "Running chutney verify to validate network connectivity (exit + HS)..."
echo "This includes proper HS timing waits to avoid descriptor lookup flakiness."
timeout 5m ./chutney verify "${CHUTNEY_NETWORK}"
echo "Chutney verify passed - network connectivity confirmed."

# Use Chutney's built-in hsaddress.sh tool to get the HS hostname
# The tool looks in ${CHUTNEY_DATA_DIR}/nodes/*h*/hidden_service/hostname
export CHUTNEY_PATH="${CHUTNEY_DIR}"
HS_HOSTNAME=$("${CHUTNEY_DIR}/tools/hsaddress.sh" 2>/dev/null | head -n 1 | sed 's/^Node [^:]*: //')

if [ -z "${HS_HOSTNAME}" ]; then
  echo "ERROR: Could not get HS hostname from hsaddress.sh"
  echo "Debugging: listing nodes directory"
  ls -la "${CHUTNEY_DATA_DIR}/nodes" 2>&1 || echo "(nodes dir not found)"
  for d in "${CHUTNEY_DATA_DIR}"/nodes/*h*; do
    echo "Node dir: $d"
    ls -la "$d/hidden_service" 2>&1 || echo "(no hidden_service dir)"
  done
  exit 1
fi

# Write the hostname to a temp file that the TypeScript test can read
export TOR_TS_HS_HOSTNAME_PATH="${CHUTNEY_DATA_DIR}/hs_hostname.txt"
echo "${HS_HOSTNAME}" > "${TOR_TS_HS_HOSTNAME_PATH}"
echo "HS hostname: ${HS_HOSTNAME}"

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
  grep -nE "^(SocksPort|ORPort|DirPort|ExitRelay|ExitPolicy|ExitPolicyRejectLocalInterfaces|ExitPolicyRejectPrivate|ClientRejectInternalAddresses|ClientDNSRejectInternalAddresses|ReducedExitPolicy|HiddenServiceDir|HiddenServicePort)\\b" "${torrc}" || true
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
      echo "=== chutney integration test: hidden-service finished at $(date -Is) ==="
      ;;
    *)
      echo "Unknown TOR_TS_CHUTNEY_TESTS entry: ${t}"
      exit 1
      ;;
  esac
done

