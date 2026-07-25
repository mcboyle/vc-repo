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
PREBUILT=0                               # set when we use a binary someone else built (see Tier 0)
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }
pend() { echo "  PENDING-INTEGRATION: $1"; PEND=$((PEND+1)); }
keyok(){ echo "  PASS (key re-derived + dm-crypt reached; fs step n/a for --filesystem=none): $1"; PASS=$((PASS+1)); }
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
	# return 2 = "derived key was CORRECT and the mount reached dm-crypt". Two signatures, same meaning:
	#   * container (no kernel dm): the table load fails with a device-mapper/dmsetup error.
	#   * real dm box + --filesystem=none: the dm mapping IS created (/dev/mapper/veracryptN) and the
	#     mount then fails at the FILESYSTEM step ("wrong fs type ... on /dev/mapper/veracryptN"), because
	#     a --filesystem=none volume carries no filesystem. A /dev/mapper/veracrypt* node only ever
	#     appears for a CORRECT key — a wrong key stops at the header (Incorrect password) and never loads
	#     a mapping — so this is a genuine key-level PASS, and a stronger one than the container case.
	#     (Without this arm, the harness's positive round-trips PASS in a container but FAIL on a VM.)
	grep -qiE "device-mapper|dmsetup|/dev/mapper/control|/dev/mapper/veracrypt" "$log" && return 2
	grep -qiE "Incorrect password|Incorrect PRF" "$log" && return 3
	return 1
}

# THE ONE FLAG LIST. Declared at top level, NOT inside the build branch below, because it is used by
# two steps that must agree:
#   - the Tier 0 build, and
#   - Tier 2b, which passes it to open_roundtrip.sh, which resolves it to a -D set and compares that
#     against src/.build-flags, REFUSING on any mismatch.
# It used to be assigned inside the `else` (build-it-ourselves) branch. When a veracrypt binary was
# already present that branch never ran, FLAGS was empty, and Tier 2b's `${FLAGS:-}` silently fell
# through to open_roundtrip.sh's OWN defaults — a different set (FLASH_WARN in, BALLOON/ADIANTUM out).
# Tier 2b then compared the wrong flag set against the archives and reported a hard FAIL that looked
# like a crypto failure. Same class as the mixed-build hazard the stamp exists to catch, one level up:
# the guard was fine, the thing being handed to it was wrong.
#
# EVERY SELF-GATING STEP'S FLAG MUST BE IN THIS LIST. Several steps below gate themselves on evidence
# that the feature was actually compiled in — `ar t Volume.a | grep EncryptionModeAdiantum` for
# Adiantum, `$VC --help | grep -- --ns-server` for network-share — so that a build without the flag
# SKIPs instead of reporting a false failure. That is the right behaviour, but it has a trap: if the
# flag is missing HERE, the gate is never satisfied and the step can ONLY ever skip. It looks self-gating
# and honest while silently testing nothing. Both ADIANTUM_MODE=1 and NETSHARE=1 were in exactly that
# state. Conversely, if the build carries a flag this list omits, Tier 2b's stamp comparison fails.
# Rule: a step's gate and this list must agree, in both directions.
FLAGS="NOGUI=1 KEYSLOTS=1 KEYSCRUB=1 DURESS=1 ARGON2PARAMS=1 BALLOON=1 SHAMIRMAC=1 SHARECODE=1 HKF_SIMULATOR=1 ADIANTUM_MODE=1 NETSHARE=1 HCTR2_MODE=1 V2FORMAT=1"

echo "=== Tier 0: build the fork with the feature flags ==="
# A default build must stay byte-for-byte stock; the flags are all opt-in.
if command -v make >/dev/null 2>&1; then
  if [ -x "$VC" ]; then
    ok "veracrypt binary present ($VC) — using it (pass a path as arg 1 to override)"
    # A supplied binary was built elsewhere, under flags this script did not choose. Tier 2b's stamp
    # comparison would then be measuring someone else's build against our list, so let it say so.
    PREBUILT=1
  else
    # clang is the default; gcc also works now (the redundant `static VC_INLINE` in chacha256.c +
    # chachaRng.c that made gcc hard-error with "duplicate 'static'" has been removed).
    # HKF_SIMULATOR (not just HKF) so the simulator round-trip below can run — testing only, never ship.
    command -v clang >/dev/null 2>&1 && { export CC=clang CXX=clang++; }
    # Build via scripts/build-product.sh, NOT bare `make`, for two reasons that both bit this harness:
    #  1. TRUE clean. `make clean` leaves Common/*.o in place and make does not rebuild on -D changes,
    #     so an object from a differently-flagged build is silently reused and the binary is MIXED —
    #     which fails as wrong behaviour (a volume that will not open), not as a build error.
    #  2. IT WRITES src/.build-flags. Tier 2b's guard compares against that stamp. Building with bare
    #     make leaves the stamp reflecting whatever last ran build-product.sh, so Tier 2b would check
    #     this run's flags against a stale stamp and fail for a reason that has nothing to do with the
    #     code under test. CLAUDE.md already says to prefer build-product.sh; this makes it structural.
    echo "  building: scripts/build-product.sh $FLAGS"
    if "$HERE/../../scripts/build-product.sh" $FLAGS >/"$WORK"/build.log 2>&1; then
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
  # Balloon needs a BALLOON=1 binary. When a prebuilt binary is supplied, its resolved -D set is stamped
  # in src/.build-flags; only run this if that stamp carries VC_ENABLE_BALLOON_KDF. A stamp that omits it
  # (e.g. a STEP-2 build without BALLOON=1) would fail create as a flag-set MISMATCH, not a Balloon bug.
  # No stamp at all = the harness self-built above with BALLOON=1 in FLAGS, so run it.
  if [ ! -f "$SRC/.build-flags" ] || grep -q VC_ENABLE_BALLOON_KDF "$SRC/.build-flags"; then
    roundtrip "balloon" "--hash=Balloon" "--hash=Balloon"           # step 38: --hash Balloon
  else
    skip "balloon round-trip — supplied binary's stamp lacks VC_ENABLE_BALLOON_KDF (rebuild with BALLOON=1 to test)"
  fi
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
  # --- Keyslots enroll/open/rotate/revoke/list (needs a build with KEYSLOTS=1) ---
  # The keyslot ops live entirely in the primary header slack [512,64K) and never touch slot 0 (the
  # native header) or the body — so the whole lifecycle is provable WITHOUT the kernel: a keyslot-open
  # reports whether the passphrase recovers the exact master key (== can mount). Full round-trip:
  # add P2 -> opens & matches; wrong pass -> no open; add P3, kill 0, P2 gone / P3 stays; rotate; and
  # a byte-diff proving the 512-byte header + data region are untouched.
  if "$VC" --text --help 2>&1 | grep -q "keyslot-add"; then
    ksv="$WORK/ks.hc"; P1="ks-native-1"; P2="ks-second-2"; P3="ks-third-3"
    if "$VC" --text --create "$ksv" --size=10M --password="$P1" --pim=0 --keyfiles="" \
          --encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
          --random-source=/dev/urandom >/dev/null 2>&1; then
      cp "$ksv" "$ksv.orig"
      ksok() { "$VC" --text --keyslot-open "$ksv" --password="$1" --new-password="$2" --pim=0 --keyfiles="" 2>&1 | grep -qi "matches the native"; }
      "$VC" --text --keyslot-add "$ksv" --password="$P1" --new-password="$P2" --pim=0 --keyfiles="" >/dev/null 2>&1
      ksok "$P1" "$P2"  && ok  "keyslots: enrolled slot opens & recovers the exact master key" \
                        || bad "keyslots: enrolled slot did not recover the master key"
      ksok "$P1" "wrongpass" && bad "keyslots: WRONG passphrase opened a slot" \
                             || ok  "keyslots: wrong passphrase correctly rejected"
      # add a 2nd slot, revoke the 1st, confirm P2 gone and P3 stays
      "$VC" --text --keyslot-add "$ksv" --password="$P1" --new-password="$P3" --pim=0 --keyfiles="" >/dev/null 2>&1
      "$VC" --text --keyslot-kill=0 "$ksv" >/dev/null 2>&1
      { ! ksok "$P1" "$P2"; } && ksok "$P1" "$P3" \
          && ok  "keyslots: revoke removes exactly the killed slot (P2 gone, P3 opens)" \
          || bad "keyslots: revoke did not behave (P2 still opens or P3 lost)"
      # rotate P3 -> a new passphrase using P3 itself as the opening credential
      "$VC" --text --keyslot-rotate "$ksv" --password="$P3" --new-password="ks-fourth-4" --pim=0 --keyfiles="" >/dev/null 2>&1
      { ! ksok "$P1" "$P3"; } && ksok "$P1" "ks-fourth-4" \
          && ok  "keyslots: rotate retires the old slot and installs the new one" \
          || bad "keyslots: rotate did not swap the slot"
      # the native 512-byte header and the data body must be byte-identical throughout
      cmp -s <(head -c 512 "$ksv.orig") <(head -c 512 "$ksv") \
          && ok  "keyslots: native 512-byte header untouched" \
          || bad "keyslots: native header changed"
      cmp -s <(tail -c 5242880 "$ksv.orig") <(tail -c 5242880 "$ksv") \
          && ok  "keyslots: data region untouched" \
          || bad "keyslots: data region changed"

      # --- sidecar backend: slots live in a SEPARATE file; the volume is byte-untouched ---
      if "$VC" --text --help 2>&1 | grep -q "keyslot-backend"; then
        cp "$ksv" "$ksv.presc"; sc="$WORK/ks.sidecar"
        "$VC" --text --keyslot-add "$ksv" --keyslot-backend=sidecar --keyslot-sidecar="$sc" \
              --password="$P1" --new-password="sidecar-pass" --pim=0 --keyfiles="" >/dev/null 2>&1
        cmp -s "$ksv.presc" "$ksv" \
            && ok  "keyslots sidecar: volume byte-untouched (slots in a separate file)" \
            || bad "keyslots sidecar: volume changed"
        "$VC" --text --keyslot-open "$ksv" --keyslot-backend=sidecar --keyslot-sidecar="$sc" \
              --password="$P1" --new-password="sidecar-pass" --pim=0 --keyfiles="" 2>&1 | grep -qi "matches the native" \
            && ok  "keyslots sidecar: slot opens & recovers the master key" \
            || bad "keyslots sidecar: slot did not open"
        "$VC" --text --keyslot-open "$ksv" --keyslot-backend=sidecar --keyslot-sidecar="$sc" \
              --password="$P1" --new-password="wrong" --pim=0 --keyfiles="" 2>&1 | grep -qi "matches the native" \
            && bad "keyslots sidecar: WRONG passphrase opened a slot" \
            || ok  "keyslots sidecar: wrong passphrase rejected"

        # --- deniable backend: a bare record at a passphrase-derived offset in the DATA region;
        #     the header region [0,64K) is byte-untouched and the slot is not enumerable ---
        cp "$ksv" "$ksv.preden"
        "$VC" --text --keyslot-add "$ksv" --keyslot-backend=deniable \
              --password="$P1" --new-password="deniable-pass" --pim=0 --keyfiles="" >/dev/null 2>&1
        cmp -s <(head -c 65536 "$ksv.preden") <(head -c 65536 "$ksv") \
            && ok  "keyslots deniable: header region [0,64K) byte-untouched" \
            || bad "keyslots deniable: header region changed"
        "$VC" --text --keyslot-open "$ksv" --keyslot-backend=deniable \
              --password="$P1" --new-password="deniable-pass" --pim=0 --keyfiles="" 2>&1 | grep -qi "matches the native" \
            && ok  "keyslots deniable: passphrase-derived slot opens & recovers the master key" \
            || bad "keyslots deniable: slot did not open"
        "$VC" --text --keyslot-open "$ksv" --keyslot-backend=deniable \
              --password="$P1" --new-password="wrong" --pim=0 --keyfiles="" 2>&1 | grep -qi "matches the native" \
            && bad "keyslots deniable: WRONG passphrase opened a slot" \
            || ok  "keyslots deniable: wrong passphrase rejected"
      else
        skip "keyslot sidecar/deniable backends — binary built without --keyslot-backend"
      fi
    else
      bad "keyslots: base volume create failed"
    fi
  else
    skip "keyslots lifecycle — binary built without KEYSLOTS=1"
  fi
  # --- Mount-time keyslot auto-search: a plain --mount tries keyslots after the native header fails,
  #     mounting from a normal slot and FIRING THE DURESS ACTION on a duress slot. Both are observable
  #     without the kernel: a normal-slot mount reaches dm-crypt (key recovered + header rebuilt), while
  #     a duress-slot mount prints the duress message and never touches the volume.
  if "$VC" --text --help 2>&1 | grep -q "keyslot-add"; then
    av="$WORK/autos.hc"; AP1="autos-native-1"; AP2="autos-normal-2"; AP3="autos-duress-3"; mkdir -p "$WORK/a.mnt"
    if "$VC" --text --create "$av" --size=10M --password="$AP1" --pim=0 --keyfiles="" \
          --encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
          --random-source=/dev/urandom >/dev/null 2>&1; then
      "$VC" --text --keyslot-add "$av" --password="$AP1" --new-password="$AP2" --pim=0 --keyfiles="" >/dev/null 2>&1
      "$VC" --text --keyslot-add "$av" --password="$AP1" --new-password="$AP3" --keyslot-duress --pim=0 --keyfiles="" >/dev/null 2>&1
      amount() { "$VC" --text --mount "$av" "$WORK/a.mnt" --password="$1" --pim=0 --keyfiles="" \
                 --protect-hidden=no --non-interactive --slot="$2" 2>&1; }
      # normal keyslot -> auto-search recovers the VMK, rebuilds the header, reaches the kernel step
      amount "$AP2" 5 >/"$WORK/a.norm.log" 2>&1
      classify_mount_log "$WORK/a.norm.log"; [ $? = 2 ] \
          && ok  "keyslots auto-search: a plain --mount with a NORMAL slot passphrase mounts via the slot (key recovered, header rebuilt)" \
          || bad "keyslots auto-search: normal-slot --mount did not recover via the keyslot"
      # duress keyslot -> fires the duress action; the volume is never opened (no dm-crypt / no Incorrect)
      amount "$AP3" 6 >/"$WORK/a.dur.log" 2>&1
      if grep -qi "Duress keyslot" "$WORK/a.dur.log" && ! grep -qiE "device-mapper|Incorrect password" "$WORK/a.dur.log"; then
        ok "keyslots auto-search: a plain --mount with a DURESS slot passphrase fires the duress action (nothing mounted)"
      else
        bad "keyslots auto-search: duress slot did not fire the duress action"
      fi
    else
      bad "keyslots auto-search: base volume create failed"
    fi
  else
    skip "keyslots mount-time auto-search — binary built without keyslots"
  fi
  # --- Duress passphrase: register a (salt, tag), then prove recognition ROUTES a mount to the safe
  #     duress action instead of the mount path. The distinguishing observable needs no kernel: a
  #     recognised duress passphrase never touches the volume (no dm-crypt / no header read), while any
  #     other credential goes to the normal mount path (dm-crypt error here, or Incorrect password).
  if "$VC" --text --help 2>&1 | grep -q "duress-register"; then
    dv="$WORK/duress.hc"; DRP="real-pass-1111"; DDP="duress-pass-9999"; mkdir -p "$WORK/d.mnt"
    if "$VC" --text --create "$dv" --size=10M --password="$DRP" --pim=0 --keyfiles="" \
          --encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
          --random-source=/dev/urandom >/dev/null 2>&1; then
      dreg="$("$VC" --text --duress-register --new-password="$DDP" 2>&1)"
      dsalt="$(printf '%s' "$dreg" | grep -oE 'duress-salt=[0-9a-f]+' | cut -d= -f2)"
      dtag="$( printf '%s' "$dreg" | grep -oE 'duress-hash=[0-9a-f]+' | cut -d= -f2)"
      if [ "${#dsalt}" = 32 ] && [ "${#dtag}" = 64 ]; then
        ok "duress: --duress-register prints a 16-byte salt + 32-byte tag"
      else
        bad "duress: register did not print a well-formed (salt, tag)"
      fi
      dmount() { "$VC" --text --mount "$dv" "$WORK/d.mnt" --password="$1" --duress-salt="$2" \
                 --duress-hash="$3" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive 2>&1; }
      # duress passphrase + registered tag -> duress action: NO dm-crypt / NO incorrect-password (the
      # volume is never opened).
      dout="$(dmount "$DDP" "$dsalt" "$dtag")"
      if printf '%s' "$dout" | grep -qiE "device-mapper|Incorrect password|Incorrect PRF"; then
        bad "duress: registered duress passphrase reached the mount path (not routed to duress)"
      else
        ok "duress: registered passphrase routes to the safe duress action (volume never opened)"
      fi
      # real passphrase -> normal mount path (reaches dm-crypt = key OK, kernel missing).
      # (Write to a real file: classify_mount_log greps its input twice, which a process-substitution
      # FIFO cannot serve.)
      dmount "$DRP" "$dsalt" "$dtag" >/"$WORK/d.real.log" 2>&1
      classify_mount_log "$WORK/d.real.log"; [ $? = 2 ] \
          && ok  "duress: the real passphrase still mounts normally (not hijacked)" \
          || bad "duress: real passphrase did not follow the normal mount path"
      # duress passphrase + WRONG tag -> not recognised -> normal mount path (Incorrect password, since
      # the duress passphrase is not the volume's real password).
      dmount "$DDP" "$dsalt" "0000000000000000000000000000000000000000000000000000000000000000" >/"$WORK/d.wrong.log" 2>&1
      classify_mount_log "$WORK/d.wrong.log"; [ $? = 3 ] \
          && ok  "duress: wrong tag is not recognised (falls through to the normal mount path)" \
          || bad "duress: wrong tag was mis-recognised as duress"
    else
      bad "duress: base volume create failed"
    fi
  else
    skip "duress register/recognition — binary built without --duress-register (DURESS=1)"
  fi
  # Adiantum wide-block EncryptionMode shim. Self-gating on the archive actually carrying the object, so
  # a build without ADIANTUM_MODE=1 SKIPs instead of reporting a false failure. Lives in realbuild/
  # because it links the real Volume.a/Platform.a — it is NOT part of the self-contained suite.
  if ar t "$SRC/Volume/Volume.a" 2>/dev/null | grep -q EncryptionModeAdiantum; then
    if VC_AM_SKIP_BUILD=1 bash "$HERE/adiantum_mode.sh" >/"$WORK/am.log" 2>&1; then
      ok "Adiantum EncryptionMode shim over the real base (wide-block diffusion measured)"
    else
      bad "Adiantum EncryptionMode shim failed"; sed 's/^/      /' "$WORK/am.log"
    fi
  else
    skip "Adiantum EncryptionMode shim — product not built with ADIANTUM_MODE=1"
  fi

  # HCTR2 EncryptionMode shim — the OTHER wide-block mode (D-4: HCTR2 where AES-NI is present,
  # Adiantum where it is not). Same self-gating shape; NOTE its flag is in FLAGS above, or this could
  # only ever skip.
  if ar t "$SRC/Volume/Volume.a" 2>/dev/null | grep -q EncryptionModeHctr2; then
    if VC_H2_SKIP_BUILD=1 bash "$HERE/hctr2_mode.sh" >/"$WORK/h2.log" 2>&1; then
      ok "HCTR2 EncryptionMode shim over the real base (wide-block diffusion measured)"
    else
      bad "HCTR2 EncryptionMode shim failed"; sed 's/^/      /' "$WORK/h2.log"
    fi
  else
    skip "HCTR2 EncryptionMode shim — product not built with HCTR2_MODE=1"
  fi

  # V2 mode DISCOVERY needs BOTH wide-block classes present, hence the two-object gate.
  if ar t "$SRC/Volume/Volume.a" 2>/dev/null | grep -q EncryptionModeHctr2 \
     && ar t "$SRC/Volume/Volume.a" 2>/dev/null | grep -q EncryptionModeAdiantum; then
    if VC_V2_SKIP_BUILD=1 bash "$HERE/v2_mode_discovery.sh" >/"$WORK/v2d.log" 2>&1; then
      ok "V2 mode discovery discriminates between the two real wide-block EncryptionMode classes"
    else
      bad "V2 mode discovery failed"; sed 's/^/      /' "$WORK/v2d.log"
    fi
  else
    skip "V2 mode discovery — needs BOTH HCTR2_MODE=1 and ADIANTUM_MODE=1"
  fi

  pend "duress-dismount of ACTUALLY-MOUNTED volumes (dismount-all + scrub needs mounted volumes = kernel dm-crypt; the routing + registration above is proven)"
  # Network-share --ns-* CLI: enrol + unlock against a real MR server over TCP. Self-gating: the probe
  # only runs when the binary actually carries the option, so a build without NETSHARE=1 SKIPs rather
  # than reporting a false failure.
  if "$VC" --help 2>&1 | grep -q -- "--ns-server"; then
    if bash "$HERE/netshare_cli.sh" >/"$WORK/nscli.log" 2>&1; then
      ok "network-share --ns-* enrol + unlock against a live MR server (positive control earned first)"
    else
      bad "network-share --ns-* CLI failed"; sed 's/^/      /' "$WORK/nscli.log"
    fi
  else
    skip "network-share --ns-* CLI — binary built without NETSHARE=1"
  fi
fi

echo; echo "=== Tier 2b: in-process Volume::Open round-trip (library-level, no kernel) ==="
# Links the real Core/Volume/Platform archives and calls Volume::Open directly (open_roundtrip.sh):
# correct password opens + recovers a non-trivial master key, wrong password rejects, and — on an
# HKF_SIMULATOR build — correct factor opens while wrong-factor / password-alone reject (2FA, through
# the salt-bound T2-1 derivation). No kernel dm-crypt. Reuses the product this script already built.
if [ -f "$SRC/Volume/Volume.a" ] && [ -f "$SRC/Core/Core.a" ] && [ -f "$SRC/Platform/Platform.a" ]; then
  if VC_OR_SKIP_BUILD=1 bash "$HERE/open_roundtrip.sh" $FLAGS >/"$WORK/or.log" 2>&1; then
    ok "in-process Volume::Open round-trip (plain open/reject + factor 2FA) — open_roundtrip.sh"
  elif [ "$PREBUILT" = 1 ] && grep -q "DIFFERENT feature set" "$WORK/or.log"; then
    # Not a test failure: the archives came from someone else's build with different -D flags, so the
    # stamp guard correctly refused. Reporting FAIL here would blame the crypto for a provisioning
    # mismatch — the exact misdiagnosis this project has paid for twice. Say what is actually wrong.
    skip "in-process Volume::Open round-trip — supplied build's flags differ from this harness's set (rebuild with: scripts/build-product.sh $FLAGS)"
    sed 's/^/    /' "$WORK/or.log" | grep -E "flag stamp|harness flag set"
  else
    bad "in-process Volume::Open round-trip failed"; sed 's/^/    /' "$WORK/or.log" | tail -15
  fi
else
  skip "in-process Volume::Open round-trip — product archives absent (a prebuilt binary was supplied, not built here)"
fi

echo; echo "=== Tier 3: real hardware (OUT OF SCOPE — documented, needs devices) ==="
skip "YubiKey / FIDO2 USB round-trip (physical token)"
skip "KeyScrub logind screen-lock / udev new-device triggers (desktop session)"
skip "TPM PCR-sealing (real or software TPM)"

echo; echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP pending=$PEND"
[ "$FAIL" = 0 ] && exit 0 || exit 1
