#!/usr/bin/env bash
# ==========================================================================
# mhr-cfw — One‑click launcher (Linux / macOS)
# Creates a local virtualenv, installs dependencies, runs the setup wizard
# if needed, and starts the proxy server.
# ==========================================================================

set -o errexit -o nounset -o pipefail
shopt -s inherit_errexit 2>/dev/null || true

# ── Colour helpers (fallback to plain text if no tty) ───────────────
if [[ -t 1 ]]; then
    BOLD="\033[1m";    RESET="\033[0m"
    GREEN="\033[32m";  YELLOW="\033[33m"
    RED="\033[31m";    CYAN="\033[36m"
else
    BOLD=""; RESET=""; GREEN=""; YELLOW=""; RED=""; CYAN=""
fi

msg()  { echo -e "${GREEN}[*]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[X]${RESET} $*" >&2; }
banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║          mhr-cfw   launcher              ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ── Locate a suitable Python 3.10+ interpreter ──────────────────────
find_python() {
    for candidate in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$candidate" &>/dev/null; then
            ver=$("$candidate" -c 'import sys; print(sys.version_info.major, sys.version_info.minor)' 2>/dev/null || echo "0 0")
            read -r major minor <<< "$ver"
            if (( major >= 3 && minor >= 10 )); then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

# ── Entry point ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

banner

PYTHON=$(find_python) || {
    err "Python 3.10+ not found. Please install it and re-run this script."
    exit 1
}
msg "Using Python: $($PYTHON --version)"

# Create virtual environment if it doesn't exist
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    msg "Creating virtual environment in $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR" || {
        err "Failed to create virtual environment. Make sure python3-venv (or equivalent) is installed."
        exit 1
    }
fi

VPY="$VENV_DIR/bin/python"

# Upgrade pip and install dependencies
msg "Installing dependencies ..."
"$VPY" -m pip install --disable-pip-version-check -q --upgrade pip || true

if [[ -f requirements.txt ]]; then
    if ! "$VPY" -m pip install --disable-pip-version-check -q -r requirements.txt; then
        warn "Primary PyPI install failed. Trying with default timeout settings..."
        PIP_DEFAULT_TIMEOUT=120 "$VPY" -m pip install --disable-pip-version-check -r requirements.txt || {
            err "Dependency installation failed. Check network and try again."
            exit 1
        }
    fi
else
    warn "No requirements.txt found. Installing minimal packages..."
    "$VPY" -m pip install --disable-pip-version-check -q rich certifi || true
fi

# Run the setup wizard if config.json is missing
if [[ ! -f config.json ]]; then
    msg "No config.json found — launching setup wizard ..."
    "$VPY" setup.py || {
        err "Setup wizard failed. Please run 'python setup.py' manually."
        exit 1
    }
fi

# Warn if auth_key or script_id still contain placeholders (quick sanitiy check)
if "$VPY" -c "import json; c=json.load(open('config.json')); assert c.get('auth_key') not in ('','CHANGE_ME_TO_A_STRONG_SECRET','your-secret-password-here')" 2>/dev/null; then
    : # ok
else
    warn "Your config.json still contains a placeholder auth_key or missing required fields."
    warn "Run the setup wizard again:  $VPY setup.py"
    exit 1
fi

echo
msg "Starting mhr-cfw ..."
echo

# Pass all command-line arguments to main.py
exec "$VPY" main.py "$@"