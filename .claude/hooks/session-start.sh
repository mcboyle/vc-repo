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
    # default: compile the verification harnesses with clang (the suite prefers it); gcc also works now
    # that the redundant `static VC_INLINE` in Crypto/chacha256.c + chachaRng.c is removed.
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
# The COMPLETE set needed to build the fork end to end, learned from an actual build:
#   wxWidgets 3.2 (GUI/CLI), libpcsclite-dev + yasm (STOCK VeraCrypt deps — smartcard headers and the
#   x86-64 AES assembler; without them the build stops in stock code, not the fork's), libfido2 +
#   libfuse (mount), and libykpers-1 for YubiKey. Some base images already ship several of these.
if [ "${CLAUDE_CODE_REMOTE:-}" = "true" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    # A broken third-party PPA (e.g. deadsnakes/ondrej) can make `apt-get update` fail for the WHOLE
    # archive, blocking even main-archive packages. Disable any such PPA best-effort so the main
    # archive still resolves. (Only touches apt sources in the ephemeral sandbox, never the repo.)
    for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
      [ -f "$f" ] || continue
      if grep -qiE "deadsnakes|ondrej|ppa\.launchpad" "$f" 2>/dev/null; then
        sudo mv "$f" "$f.disabled" 2>/dev/null && log "disabled broken PPA: $(basename "$f")" || true
      fi
    done
    log "installing full real-build dep set (best-effort)"
    sudo apt-get update -y >/dev/null 2>&1 || true
    # libwxgtk3.2-dev is named differently across releases; try the common candidates.
    for pkg in build-essential pkg-config yasm \
               libwxgtk3.2-dev libwxgtk3.0-gtk3-dev \
               libpcsclite-dev libfido2-dev libfuse3-dev libfuse-dev libykpers-1-dev; do
      sudo apt-get install -y "$pkg" >/dev/null 2>&1 || true
    done
    # Report exactly what a product build can/can't do, so a session knows before it tries.
    havewx=no; ls /usr/include/wx-* >/dev/null 2>&1 && havewx=yes
    havepcsc=no; ls /usr/include/PCSC/pcsclite.h /usr/include/pcsclite.h >/dev/null 2>&1 && havepcsc=yes
    haveyasm=no; command -v yasm >/dev/null 2>&1 && haveyasm=yes
    log "build deps: wxWidgets=$havewx  libpcsclite-dev=$havepcsc  yasm=$haveyasm"
    if [ "$havewx" = yes ] && [ "$havepcsc" = yes ]; then
      log "product build ready:  cd src && make NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1$([ $haveyasm = yes ] || echo ' NOASM=1')"
    else
      log "product build NOT fully provisionable here (apt offline/locked). The verification suite still works: cd verification && ./build_and_verify.sh"
      [ "$havepcsc" = no ] && log "  missing libpcsclite-dev — the one stock dep that blocked the build in this image"
    fi
  fi
else
  log "local session — skipping real-build dep install (set CLAUDE_CODE_REMOTE=true to force)"
fi

log "ready. Verify:  cd verification && ./build_and_verify.sh   |  Build: see docs/SESSION-STARTUP.md"
exit 0
