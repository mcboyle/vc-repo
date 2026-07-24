#!/bin/bash
# build-product.sh — build the VeraCrypt fork as a real console (NOGUI) product and smoke-test it.
#
# WHY THIS EXISTS
# The verification suite (verification/build_and_verify.sh) compiles the fork's Common/Crypto modules
# individually and links tiny harnesses — it proves the *algorithms*, but it never links the full
# product, so the C++ mount/create wiring (Volume/, Core/, Main/) was historically "real-build-only"
# and unverified in CI. This script builds the actual `veracrypt` binary + the Volume.a/Core.a archives,
# so (a) CI can gate every PR on the product still linking, and (b) a follow-up library-level acceptance
# harness can link the real objects for create->header-decrypt round-trips (no kernel needed).
#
# It is idempotent, non-interactive, and usable from both CI (.github/workflows) and the Claude Code
# SessionStart hook. Extra `make` args pass through, e.g.:
#     scripts/build-product.sh NOGUI=1 HKF=1 HKF_SIMULATOR=1 HKF_MIX_V2_SALTBIND=1
# With no args it defaults to a plain NOGUI console build.
#
# Deps (Ubuntu): the STOCK VeraCrypt build needs libwxgtk3.2-dev + libpcsclite-dev + yasm; the fork's
# hardware factors additionally need libfido2-dev + libykpers-1-dev, and mounting needs libfuse-dev.
# Kernel dm-crypt mounting is NOT exercised here (containers lack the device-mapper driver) — this is a
# BUILD + binary smoke, plus the library-level round-trip that a separate harness performs.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
: "${CC:=clang}"
: "${CXX:=clang++}"
JOBS="$(nproc 2>/dev/null || echo 2)"

# Default to a plain console build when no make args are supplied.
MAKE_ARGS=("$@")
if [ "${#MAKE_ARGS[@]}" -eq 0 ]; then MAKE_ARGS=(NOGUI=1); fi

log() { echo "[build-product] $*"; }

# --- 1. Build dependencies (best-effort; apt failures do not hard-fail unless the build then fails) ---
DEPS="build-essential yasm libwxgtk3.2-dev libpcsclite-dev libfuse-dev libfido2-dev libykpers-1-dev pkg-config"
if command -v apt-get >/dev/null 2>&1; then
	log "ensuring build deps ($DEPS)"
	sudo apt-get update -y >/dev/null 2>&1 || apt-get update -y >/dev/null 2>&1 || true
	# shellcheck disable=SC2086
	sudo apt-get install -y --no-install-recommends $DEPS >/dev/null 2>&1 \
		|| apt-get install -y --no-install-recommends $DEPS >/dev/null 2>&1 \
		|| log "WARNING: apt could not install every dep (build may still succeed if already present)"
fi

# --- 2. Build ------------------------------------------------------------------------------------------
# TRUE clean. `make clean` is NOT sufficient here: it leaves the Common/*.o objects in place, so an object
# compiled under a previous flag set (e.g. HardwareKeyFactor.o built HKF-on/KEYSCRUB-off) is silently
# reused when the flags change — producing a MIXED binary or a bogus link error (a stale HardwareKeyFactor.o
# lacking HKFScrubActiveConfig fails the KEYSCRUB link). make does not rebuild objects on -D changes alone
# (docs/REAL-BUILD-VALIDATION.md), so we remove every build product explicitly before compiling.
log "true clean (remove all *.o / *.a / *.d + binary, not just 'make clean')"
make -C "$ROOT/src" clean >/dev/null 2>&1 || true
find "$ROOT/src" \( -name '*.o' -o -name '*.a' -o -name '*.d' \) -delete 2>/dev/null || true
rm -f "$ROOT/src/Main/veracrypt" 2>/dev/null || true
log "building product: make ${MAKE_ARGS[*]} CC=$CC CXX=$CXX -j$JOBS"
if ! make -C "$ROOT/src" "${MAKE_ARGS[@]}" CC="$CC" CXX="$CXX" -j"$JOBS"; then
	log "PRODUCT BUILD FAILED"
	exit 1
fi

# --- 3. Smoke: the binary links and runs, and the linkable archives exist -----------------------------
BIN="$ROOT/src/Main/veracrypt"
if [ ! -x "$BIN" ]; then
	log "expected binary not found: $BIN"
	exit 1
fi
VER="$("$BIN" --version 2>&1 | head -1)"
log "built: $BIN"
log "version: $VER"
case "$VER" in
	*VeraCrypt*) ;;
	*) log "unexpected --version output"; exit 1 ;;
esac
for a in "$ROOT/src/Volume/Volume.a" "$ROOT/src/Core/Core.a"; do
	[ -f "$a" ] && log "archive present: $a" || { log "missing archive: $a"; exit 1; }
done

# --- 4. Stamp the resolved feature flags next to the archives -----------------------------------------
# A consumer that links these archives (verification/realbuild/open_roundtrip.sh) must compile itself with
# the SAME -D set, or it links a mixed binary: the harness sees one feature set and the archives another.
# That is not hypothetical — it silently produced a false "explicit Argon2 params do not round-trip"
# result that survived a whole session, because the harness and the product had been built from different
# flag sets. The stamp lets the consumer detect the mismatch instead of inferring a crypto bug from it.
STAMP="$ROOT/src/.build-flags"
make -C "$ROOT/src" -pn "${MAKE_ARGS[@]}" 2>/dev/null \
	| grep -E '^C_CXX_FLAGS :?= ' | tail -1 \
	| grep -oE '\-D(VC_ENABLE|TC)_[A-Z_0-9]*' | sort -u | tr '\n' ' ' > "$STAMP"
log "feature-flag stamp: $STAMP -> $(cat "$STAMP")"

log "OK — product builds, binary runs, Volume.a/Core.a present"
