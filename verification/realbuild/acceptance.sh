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
keyok(){ echo "  PASS (key OK, no kernel dm-crypt): $1"; PASS=$((PASS+1)); }
cleanup() { rm -rf "$WORK" 2>/dev/null; }
trap cleanup EXIT

have_root() { [ "$(id -u)" = 0 ]; }
have_loop() { have_root && command -v losetup >/dev/null 2>&1 && [ -e /dev/loop-control ]; }
have_dm()   { [ -e /dev/mapper/control ]; }   # dm-crypt table load needs this; containers often lack it
PW="acceptance-pass-1234"

# Classify a mount log when the kernel has no device-mapper (common in containers). VeraCrypt derives
# the header key and authenticates the header BEFORE it ever calls dmsetup, so the failure point is
# diagnostic: a device-mapper/dmsetup error means the key was correct and only the kernel table load is
# missing (a genuine key-level PASS in such an environment); "Incorrect password" means the derived key
# was wrong. Returns: 0 = mounted, 2 = key-correct-but-no-dm, 3 = wrong key, 1 = other.
classify_mount_log() {
	local log="$1"
	grep -qiE "device-mapper|dmsetup|/dev/mapper/control" "$log" && return 2
	grep -qiE "Incorrect password|Incorrect PRF" "$log" && return 3
	return 1
}

echo "=== Tier 0: build the fork with the feature flags ==="
# A default build must stay byte-for-byte stock; the flags are all opt-in.
if command -v make >/dev/null 2>&1; then
  if [ -x "$VC" ]; then
    ok "veracrypt binary present ($VC) — using it (pass a path as arg 1 to override)"
  else
    # clang is required in practice: gcc hard-errors on stock Crypto/chacha256.c ("duplicate static").
    # HKF_SIMULATOR (not just HKF) so the simulator round-trip below can run — testing only, never ship.
    VCC=""; command -v clang >/dev/null 2>&1 && VCC="CC=clang CXX=clang++"
    # `make clean` first: the build system does NOT rebuild objects when only -D feature flags change,
    # so objects left by a differently-flagged build would silently produce a mixed binary (this
    # exact trap produced two phantom bugs during validation — treat flag changes as clean builds).
    make -C "$SRC" clean >/dev/null 2>&1 || true
    echo "  building: make -C $SRC $VCC NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1 HKF_SIMULATOR=1"
    if make -C "$SRC" $VCC NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1 HKF_SIMULATOR=1 -j4 >/"$WORK"/build.log 2>&1; then
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
      # Mount returned non-zero. Distinguish "key correct, kernel has no dm-crypt" (still a key-level
      # PASS) from a genuine wrong-key failure, using the failure signature in the log.
      classify_mount_log "$WORK/${label}.m.log"; case $? in
        2) keyok "$label: create -> key re-derived + header authenticated (mount stopped at dm-crypt)";;
        3) bad   "$label: created but key re-derivation FAILED at mount (wrong key; see $WORK/${label}.m.log)";;
        *) bad   "$label: created but mount failed (see $WORK/${label}.m.log)";;
      esac
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

  # negative: mounting the argon2 volume with DIFFERENT params must derive a DIFFERENT key. Asserting
  # merely "does not mount" is too weak where the kernel lacks dm-crypt (nothing ever mounts), so assert
  # the *wrong-key* signature: the mount must fail specifically with "Incorrect password" (header MAC
  # failed), NOT with a device-mapper error (which would mean the key matched and the override was
  # ignored — the exact bug the real build caught). Two axes: wrong memory, and wrong iterations.
  voln="$WORK/argon2.hc"; mkdir -p "$WORK/n.mnt"
  if [ -f "$voln" ]; then
    for neg in "--argon2-memory=128 --argon2-iterations=3:wrong-memory" \
               "--argon2-memory=64 --argon2-iterations=9:wrong-iterations"; do
      nflags="${neg%%:*}"; ndesc="${neg##*:}"
      if "$VC" --text --mount "$voln" "$WORK/n.mnt" --password="$PW" --pim=0 --keyfiles="" \
            --protect-hidden=no --non-interactive --hash=Argon2 $nflags --slot=2 >/"$WORK/argon2.neg.log" 2>&1; then
        "$VC" --text --dismount "$voln" >/dev/null 2>&1; bad "argon2 $ndesc: SHOULD NOT mount"
      else
        classify_mount_log "$WORK/argon2.neg.log"; case $? in
          3) ok    "argon2 $ndesc: correctly rejected — different key derived (Incorrect password)";;
          2) bad   "argon2 $ndesc: mount reached dm-crypt with WRONG params — override NOT shaping the key";;
          *) bad   "argon2 $ndesc: unexpected failure (see $WORK/argon2.neg.log)";;
        esac
      fi
    done
  fi

  # --- HKF simulator factor round-trip (needs a build with HKF_SIMULATOR=1) ---
  # The 2FA acceptance criterion has THREE negative axes: wrong secret, no factor at all (password
  # alone must be insufficient), and — implicitly — the stock volume above proving no-factor mounts
  # still work. All classified by failure signature as with argon2.
  if "$VC" --text --help 2>&1 | grep -q "hkf-backend"; then
    HKFSEC="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    HKFBAD="ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    volh="$WORK/hkf.hc"; mkdir -p "$WORK/hkf.mnt"
    if "$VC" --text --create "$volh" --size=10M --password="$PW" --pim=0 --keyfiles="" \
          --encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
          --random-source=/dev/urandom --hkf-backend=simulator --hkf-sim-secret="$HKFSEC" \
          >/"$WORK/hkf.c.log" 2>&1; then
      if "$VC" --text --mount "$volh" "$WORK/hkf.mnt" --password="$PW" --pim=0 --keyfiles="" \
            --protect-hidden=no --non-interactive --slot=1 --hkf-backend=simulator \
            --hkf-sim-secret="$HKFSEC" >/"$WORK/hkf.m.log" 2>&1; then
        "$VC" --text --dismount "$volh" >/dev/null 2>&1
        ok "hkf-simulator: create -> mount -> dismount round-trip"
      else
        classify_mount_log "$WORK/hkf.m.log"; case $? in
          2) keyok "hkf-simulator: create -> factor mixed + key re-derived + header authenticated";;
          *) bad   "hkf-simulator: same secret did not re-derive the key (see $WORK/hkf.m.log)";;
        esac
      fi
      for neg in "--hkf-backend=simulator --hkf-sim-secret=$HKFBAD:wrong-secret" ":no-factor"; do
        nflags="${neg%%:*}"; ndesc="${neg##*:}"
        if "$VC" --text --mount "$volh" "$WORK/hkf.mnt" --password="$PW" --pim=0 --keyfiles="" \
              --protect-hidden=no --non-interactive --slot=2 $nflags >/"$WORK/hkf.neg.log" 2>&1; then
          "$VC" --text --dismount "$volh" >/dev/null 2>&1; bad "hkf-simulator $ndesc: SHOULD NOT mount"
        else
          classify_mount_log "$WORK/hkf.neg.log"; case $? in
            3) ok  "hkf-simulator $ndesc: correctly rejected (password alone / wrong secret insufficient)";;
            2) bad "hkf-simulator $ndesc: reached dm-crypt WITHOUT the right factor — factor not gating the key";;
            *) bad "hkf-simulator $ndesc: unexpected failure (see $WORK/hkf.neg.log)";;
          esac
        fi
      done
    else
      bad "hkf-simulator: create failed (see $WORK/hkf.c.log)"
    fi
  else
    skip "HKF simulator round-trip — binary built without HKF_SIMULATOR=1"
  fi

  # --- PENDING-INTEGRATION features (CLI/mount glue is the remaining real-build work) ---
  pend "keyslots enroll/open/rotate/revoke CLI (docs/KEYSLOTS-SPEC.md §9 — C++ stream adapters + CLI)"
  pend "duress-dismount end-to-end (--duress-dismount + duress passphrase; docs/DURESS-DISMOUNT-SPEC.md)"
  pend "network-share (McCallum-Relyea) enroll/unlock CLI + transport (docs/NETWORK-SHARE-SPEC.md)"
fi

echo; echo "=== Tier 3: real hardware (OUT OF SCOPE — documented, needs devices) ==="
skip "YubiKey / FIDO2 USB round-trip (physical token)"
skip "KeyScrub logind screen-lock / udev new-device triggers (desktop session)"
skip "TPM PCR-sealing (real or software TPM)"

echo; echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP pending=$PEND"
[ "$FAIL" = 0 ] && exit 0 || exit 1
