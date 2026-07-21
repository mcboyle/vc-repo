#!/bin/bash
# SessionStart hook — prepares a Claude Code (web) session to build & verify this VeraCrypt fork.
#
# Two tiers of dependency:
#   * verification suite (verification/build_and_verify.sh): needs only clang/gcc + python3 — it
#     compiles the Common/Crypto objects individually and needs no wxWidgets. These are almost always
#     already present; the hook confirms them.
#   * real product build (src && make ...): additionally needs libwxgtk3.2-dev and, for the hardware
#     factors, libykpers-1-dev + libfido2-dev (+ libfuse for mounting). The hook installs these
#     best-effort — a session that only runs the verification suite does not need them, so a failed
#     apt (offline / locked mirror) must NOT block session start.
#
# Idempotent, non-interactive, and fail-open: it never exits non-zero on an optional-dep problem.

set -uo pipefail
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

log() { echo "[session-start] $*"; }

# --- Persist env for the session (feature knobs + proxy CA already set by the platform) ---
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export VC_SRC=\"$PROJECT_DIR/src\""
    echo "export VC_VERIFY=\"$PROJECT_DIR/verification\""
    # default: compile the verification harnesses with clang (gcc rejects Crypto/chacha256.c's
    # duplicate 'static'); the suite already prefers clang, this just mirrors it for ad-hoc builds.
    echo "export CC=\"\${CC:-clang}\""
  } >> "$CLAUDE_ENV_FILE" 2>/dev/null || true
fi

# --- 1. Confirm the verification toolchain (hard requirement) ---
missing=""
command -v clang >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || missing="$missing c-compiler"
command -v make    >/dev/null 2>&1 || missing="$missing make"
command -v python3 >/dev/null 2>&1 || missing="$missing python3"
if [ -n "$missing" ]; then
  log "installing verification toolchain:$missing"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y clang make python3 >/dev/null 2>&1 || apt-get install -y clang make python3 >/dev/null 2>&1 || true
  fi
fi
command -v clang >/dev/null 2>&1 && log "clang: $(clang --version | head -1)" || log "WARNING: no clang"
command -v python3 >/dev/null 2>&1 && log "python3: $(python3 --version)" || log "WARNING: no python3"

# --- 2. Best-effort: real-build deps (only meaningful in a remote/web box; never blocks) ---
if [ "${CLAUDE_CODE_REMOTE:-}" = "true" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "installing real-build deps (best-effort: wxWidgets + YubiKey/FIDO2 + FUSE)"
    sudo apt-get update -y >/dev/null 2>&1 || true
    # libwxgtk3.2-dev is named differently across releases; try the common candidates.
    for pkg in libwxgtk3.2-dev libwxgtk3.0-gtk3-dev libykpers-1-dev libfido2-dev libfuse-dev pkg-config build-essential; do
      sudo apt-get install -y "$pkg" >/dev/null 2>&1 || true
    done
    if pkg-config --exists wxwidgets 2>/dev/null || ls /usr/include/wx-* >/dev/null 2>&1; then
      log "wxWidgets present — a full product build (src && make ...) is possible"
    else
      log "wxWidgets NOT installed (offline or unavailable) — the verification suite still works; the product build does not"
    fi
  fi
else
  log "local session — skipping real-build dep install (set CLAUDE_CODE_REMOTE=true to force)"
fi

log "ready. Verify:  cd verification && ./build_and_verify.sh   |  Build: see docs/SESSION-STARTUP.md"
exit 0
