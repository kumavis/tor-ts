#!/usr/bin/env bash
set -euo pipefail

# Installs Chutney (clone + pinned checkout + patch + pip install).
# Intended for CI usage so dependency installation is separate from test execution.

if ! command -v git >/dev/null; then
  echo "git is required"
  exit 1
fi

if ! command -v python3 >/dev/null; then
  echo "python3 is required"
  exit 1
fi

# https://gitlab.torproject.org/tpo/core/chutney
CHUTNEY_REPO_URL="https://gitlab.torproject.org/tpo/core/chutney.git"
CHUTNEY_COMMIT="0e202ad78eefca5f972d09ab0e2de8c1e36417c4"

export CHUTNEY_DIR="${CHUTNEY_DIR:-/tmp/chutney}"
rm -rf "${CHUTNEY_DIR}"
git clone "${CHUTNEY_REPO_URL}" "${CHUTNEY_DIR}"
git -C "${CHUTNEY_DIR}" checkout "${CHUTNEY_COMMIT}"

# Patch chutney's torrc template to make localhost exits work reliably in CI.
# (We keep the repo pinned above; this is an in-place CI-only patch.)
python3 - <<'PY'
from pathlib import Path
import os

torrc_py = Path(os.environ["CHUTNEY_DIR"]) / "lib/chutney/tor/torrc.py"
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

# Keep installs independent of externally managed system Python packages.
python3 -m venv "${CHUTNEY_DIR}/.venv"
"${CHUTNEY_DIR}/.venv/bin/python" -m pip install -e "${CHUTNEY_DIR}"

echo "Chutney installed in ${CHUTNEY_DIR}"
