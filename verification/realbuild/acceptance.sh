#!/usr/bin/env bash
#
# acceptance.sh — Tier-2 real-build acceptance harness (docs/REAL-BUILD-VALIDATION.md).
#
# The verification/build_and_verify.sh suite proves the crypto byte-for-byte, but it compiles the
# Common objects individually and never builds or runs the actual VeraCrypt binary. This harness is
# the missing piece: on a real Linux build box it BUILDS the fork with the feature flags and runs
# loopback volume create/mount round-trips, asserting the "core proven, integration pending" features
# actually work end to end. It is what converts a green suite into a working product.
#
# It is deliberately SELF-GATING and honest:
#   * Tier 0 (any box):        build the fork with the feature flags; a plain build stays stock.
#   * Tier 2 (root + loop dev): create/mount/dismount round-trips against a loopback container.
#   * Tier 3 (real hardware):   YubiKey/FIDO2, logind/udev, TPM — OUT OF SCOPE here (documented).
# Anything it cannot do in the current environment prints SKIP (not FAIL), so it can be dry-run
# unprivileged to check its own logic, and run for real on a build box.
#
# Features whose CLI is not yet wired print PENDING-INTEGRATION with the spec reference — so this file
# doubles as a live checklist of the remaining real-build integration work.
#
# Usage:  sudo bash verification/realbuild/acceptance.sh [/path/to/veracrypt]
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../../src" && pwd)"
VC="${1:-$SRC/Main/veracrypt}"           # built CLI binary (override as arg 1)
WORK="$(mktemp -d 2>/dev/null || echo /tmp/vcacc.$$)"; mkdir -p "$WORK"
PASS=0; FAIL=0; SKIP=0; PEND=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }
pend() { echo "  PENDING-INTEGRATION: $1"; PEND=$((PEND+1)); }
cleanup() { rm -rf "$WORK" 2>/dev/null; }
trap cleanup EXIT

have_root() { [ "$(id -u)" = 0 ]; }
have_loop() { have_root && command -v losetup >/dev/null 2>&1 && [ -e /dev/loop-control ]; }
PW="acceptance-pass-1234"

echo "=== Tier 0: build the fork with the feature flags ==="
# A default build must stay byte-for-byte stock; the flags are all opt-in.
if command -v make >/dev/null 2>&1; then
  if [ -x "$VC" ]; then
    ok "veracrypt binary present ($VC) — using it (pass a path as arg 1 to override)"
  else
    echo "  building: make -C $SRC NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1 HKF=1"
    if make -C "$SRC" NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1 HKF=1 >/"$WORK"/build.log 2>&1; then
      ok "fork built with all feature flags"
      [ -x "$VC" ] || VC="$(find "$SRC" -name veracrypt -type f -perm -u+x 2>/dev/null | head -1)"
    else
      bad "build failed (see $WORK/build.log — needs libwxgtk3.2-dev, and for HKF: libykpers-1-dev/libfido2-dev)"
    fi
  fi
else
  skip "no make in PATH — cannot build here"
fi

if [ ! -x "$VC" ]; then
  echo; echo "No runnable veracrypt binary — Tier-2 round-trips skipped. (Build on a real box, then re-run.)"
  echo; echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP pending=$PEND"
  [ "$FAIL" = 0 ] && exit 0 || exit 1
fi

# Helper: create + mount + dismount a normal volume with the given extra create/mount args.
# Args: <label> <create-extra> <mount-extra>
roundtrip() {
  local label="$1" cflags="$2" mflags="$3"
  local vol="$WORK/${label}.hc" mnt="$WORK/${label}.mnt"; mkdir -p "$mnt"
  if "$VC" --text --create "$vol" --size=10M --password="$PW" --pim=0 --keyfiles="" \
        --encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
        --random-source=/dev/urandom $cflags >/"$WORK/${label}.c.log" 2>&1; then
    if "$VC" --text --mount "$vol" "$mnt" --password="$PW" --pim=0 --keyfiles="" \
          --protect-hidden=no --slot=1 $mflags >/"$WORK/${label}.m.log" 2>&1; then
      "$VC" --text --dismount "$vol" >/dev/null 2>&1
      ok "$label: create -> mount -> dismount round-trip"
    else
      bad "$label: created but mount failed (see $WORK/${label}.m.log)"
    fi
  else
    bad "$label: create failed (see $WORK/${label}.c.log)"
  fi
}

echo; echo "=== Tier 2: loopback create/mount round-trips ==="
if ! have_loop; then
  skip "not root / no loop device — Tier-2 round-trips require 'sudo' on a real Linux box"
else
  # --- WIRED features (should pass on a real build) ---
  roundtrip "stock"   "" ""                                          # baseline (no fork feature)
  roundtrip "balloon" "--hash=Balloon" "--hash=Balloon"             # step 38: --hash Balloon
  roundtrip "argon2"  "--hash=Argon2 --argon2-memory=64 --argon2-iterations=3" \
                      "--hash=Argon2 --argon2-memory=64 --argon2-iterations=3"   # step 17/11

  # negative: mounting the argon2 volume with different params must FAIL
  voln="$WORK/argon2.hc"
  if [ -f "$voln" ]; then
    if "$VC" --text --mount "$voln" "$WORK/n.mnt" --password="$PW" --pim=0 --keyfiles="" \
          --hash=Argon2 --argon2-memory=128 --argon2-iterations=3 --slot=2 >/dev/null 2>&1; then
      "$VC" --text --dismount "$voln" >/dev/null 2>&1; bad "argon2: wrong params SHOULD NOT mount"
    else
      ok "argon2: wrong memory param correctly rejected (key differs)"
    fi
  fi

  # --- PENDING-INTEGRATION features (CLI/mount glue is the remaining real-build work) ---
  pend "keyslots enroll/open/rotate/revoke CLI (docs/KEYSLOTS-SPEC.md §9 — C++ stream adapters + CLI)"
  pend "duress-dismount end-to-end (--duress-dismount + duress passphrase; docs/DURESS-DISMOUNT-SPEC.md)"
  pend "HKF factor mount round-trip with a SIMULATOR backend (--hkf-backend simulator; docs/HARDWARE-2FA.md)"
  pend "network-share (McCallum-Relyea) enroll/unlock CLI + transport (docs/NETWORK-SHARE-SPEC.md)"
fi

echo; echo "=== Tier 3: real hardware (OUT OF SCOPE — documented, needs devices) ==="
skip "YubiKey / FIDO2 USB round-trip (physical token)"
skip "KeyScrub logind screen-lock / udev new-device triggers (desktop session)"
skip "TPM PCR-sealing (real or software TPM)"

echo; echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP pending=$PEND"
[ "$FAIL" = 0 ] && exit 0 || exit 1
