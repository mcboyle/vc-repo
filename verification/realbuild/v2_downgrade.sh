#!/bin/bash
# v2_downgrade.sh — the silent v2 downgrade, and the --v2-require assertion that refuses it.
#
# THE DEFECT (reproduced here as step [2], deliberately, as a live negative control)
#
# Nothing on disk marks a volume as v2. That is the D-10 deniability property working as intended: a v2
# tail must be indistinguishable from v1 free space to anyone without the key. The consequence is that
# mount-time discovery is a guess — read data sector 0 and its MAC-table slot, ask which mode's key
# reproduces the tag, and if nothing matches, treat the volume as v1.
#
# So an adversary with WRITE access but NO PASSWORD can zero the 16 bytes at tag slot 0. Discovery then
# matches nothing, `V2Mac` stays inert, and the volume opens as v1 with per-sector authentication simply
# ABSENT — no error, no warning, no log line. Every subsequent tampered sector reads back clean.
#
# `docs/V2-FORMAT-SPEC.md` claimed the opposite: "a keyless downgrade yields mount failure, not silent
# integrity-stripping". That argument is sound for FORGING a valid v1 volume from v2 data (which does
# need the master key) and simply does not cover STRIPPING the tags (which needs nothing). Corrected in
# that file as part of this change.
#
# WHY THE FIX IS AN OPT-IN ASSERTION AND NOT "ALWAYS REFUSE"
#
# Discovery is non-fatal by deliberate design — `Volume.cpp` argues that failing a mount because the
# tail of the disk is unreadable "would turn an availability problem into a lockout", and a genuine v1
# volume legitimately has no table to find. Both are right. Since a stripped v2 volume and a real v1
# volume are byte-indistinguishable at that point, no amount of cleverness inside discovery can tell
# them apart. Only the CALLER knows which it expects. Hence `--v2-require`.
#
# WHAT THIS SCRIPT PROVES
#   [1] an intact v2 volume opens with authentication ACTIVE;
#   [2] the defect: strip 16 bytes with no password -> still mounts, authentication silently GONE;
#   [3] --v2-require REFUSES the stripped volume and names the cause;
#   [4] --v2-require ACCEPTS an intact v2 volume (specificity: not a blanket refusal);
#   [5] a genuine v1 volume opens normally without the flag, and is refused with it (correct — it is
#       not v2; this is the assertion doing its job, not a false positive);
#   [6] --v2-ignore-tags still mounts the stripped volume, so recovery is not collateral damage.
#
# [4] and [5] are the regression-critical pair: an implementation that simply refused everything, or
# accepted everything, would pass [3] alone.
#
# ANCHOR CLASS: PROPERTY / [TWIN-ONLY]. There is no external vector set for a fork-specific mount
# policy. The weight here comes from falsifying an in-tree written claim against the real product, and
# from step [2] being a live reproduction rather than an assertion about one.
# NON-DESTRUCTIVE: file containers inside a mktemp -d.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VC="$ROOT/src/Main/veracrypt"

log()  { echo "[v2-downgrade] $*"; }
fail() { echo "[v2-downgrade] FAIL: $*" >&2; exit 1; }

[ -x "$VC" ] || fail "product not built (need scripts/build-product.sh ... V2FORMAT=1)"
"$VC" --help 2>&1 | grep -q -- "--v2-format"  || { echo "[v2-downgrade] SKIP — built without V2FORMAT=1"; exit 0; }
"$VC" --help 2>&1 | grep -q -- "--v2-require" || fail "V2FORMAT build lacks --v2-require (guard not compiled in)"

if [ "$(id -u)" != 0 ] || { [ ! -e /dev/mapper/control ] && [ ! -c /dev/fuse ]; }; then
	echo "[v2-downgrade] SKIP — needs root + a mount backend (dm-crypt or /dev/fuse)"; exit 0
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PW="downgrade-pw"; MB=20; SLOT=7

pass=0; failc=0
check() { if [ "$2" = 0 ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; failc=$((failc+1)); fi; return 0; }

mkvol() { # $1=path  $2=extra flags
	"$VC" --text --create "$1" --size=${MB}M --password="$PW" --pim=0 --keyfiles="" \
		--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
		--random-source=/dev/urandom $2 >/dev/null 2>&1
}

# Prefer kernel dm-crypt, fall back to FUSE, and report which ran — same contract as
# v2_hidden_guard.sh, so a FUSE-only pass can never be quoted as kernel coverage.
mount_vol() { # $1=path  $2..=extra flags; sets MOUNT_BACKEND
	MOUNT_BACKEND=""
	if [ -e /dev/mapper/control ]; then
		if "$VC" --text --mount "$1" --password="$PW" --pim=0 --keyfiles="" --protect-hidden=no \
			--filesystem=none --slot=$SLOT "${@:2}" >/dev/null 2>&1; then
			MOUNT_BACKEND=kernel; return 0
		fi
		"$VC" --text -d --slot=$SLOT >/dev/null 2>&1
	fi
	if [ -c /dev/fuse ]; then
		if "$VC" --text --mount "$1" --password="$PW" --pim=0 --keyfiles="" --protect-hidden=no \
			--filesystem=none --slot=$SLOT -m nokernelcrypto "${@:2}" >/dev/null 2>&1; then
			MOUNT_BACKEND=fuse; return 0
		fi
	fi
	return 1
}
mount_err() { # same, but capture stderr and always use the FUSE-capable path
	"$VC" --text --mount "$1" --password="$PW" --pim=0 --keyfiles="" --protect-hidden=no \
		--filesystem=none --slot=$SLOT -m nokernelcrypto "${@:2}" 2>&1
}
umount_vol() { "$VC" --text -d --slot=$SLOT >/dev/null 2>&1; sleep 1; }
auth_active() { "$VC" --text --list -v 2>/dev/null | grep -q "Per-sector authentication: active"; }

tbl_base() { python3 -c "
host=$(stat -c %s "$1"); ss=512; HDR=131072
tot=(host-2*HDR)//ss; u=tot
while u+(u*16+ss-1)//ss > tot: u-=1
print(HDR+u*ss)"; }

V2="$WORK/v2.hc"; V2B="$WORK/v2b.hc"; V1="$WORK/v1.hc"
mkvol "$V2"  --v2-format || fail "v2 create failed"
mkvol "$V2B" --v2-format || fail "v2 (control) create failed"
mkvol "$V1"  ""          || fail "v1 create failed"
TBL="$(tbl_base "$V2")"
log "v2 MAC table begins at offset $TBL"

log "=== [1] intact v2 opens WITH authentication ==="
mount_vol "$V2"; RC=$?
[ "$RC" -eq 0 ]; check "intact v2 mounts [backend: ${MOUNT_BACKEND:-none}]" $?
auth_active; check "--list -v reports per-sector authentication ACTIVE" $?
umount_vol

log "=== [2] THE DEFECT — strip 16 bytes, no password, authentication silently disappears ==="
BEFORE="$(python3 -c "f=open('$V2','rb');f.seek($TBL);print(f.read(16).hex())")"
python3 -c "f=open('$V2','r+b');f.seek($TBL);f.write(b'\x00'*16);f.close()"
AFTER="$(python3 -c "f=open('$V2','rb');f.seek($TBL);print(f.read(16).hex())")"
[ "$BEFORE" != "$AFTER" ]; check "tag slot 0 overwritten without the password" $?
mount_vol "$V2"; RC=$?
[ "$RC" -eq 0 ]; check "the stripped volume STILL MOUNTS (this is the defect)" $?
if auth_active; then
	check "authentication is now silently ABSENT (the defect)" 1
else
	check "authentication is now silently ABSENT (the defect)" 0
fi
umount_vol

log "=== [3] --v2-require REFUSES the stripped volume ==="
OUT="$(mount_err "$V2" --v2-require)"; RC=$?
[ "$RC" -ne 0 ]; check "mount is refused (non-zero exit)" $?
echo "$OUT" | grep -q "NOT v2-format"; check "the error says the volume is not v2-format" $?
echo "$OUT" | grep -q "WITHOUT the password"; check "the error names the keyless-strip cause" $?
umount_vol

log "=== [4] --v2-require ACCEPTS an intact v2 volume (specificity) ==="
mount_vol "$V2B" --v2-require; RC=$?
[ "$RC" -eq 0 ]; check "an intact v2 volume still mounts under --v2-require" $?
auth_active; check "and its authentication is still active" $?
umount_vol

log "=== [5] a genuine v1 volume: opens plain, refused under the assertion ==="
mount_vol "$V1"; RC=$?
[ "$RC" -eq 0 ]; check "v1 opens normally when nothing is asserted" $?
umount_vol
OUT="$(mount_err "$V1" --v2-require)"; RC=$?
[ "$RC" -ne 0 ]; check "v1 is refused under --v2-require (the assertion is doing its job)" $?
umount_vol

log "=== [6] --v2-ignore-tags still recovers the stripped volume ==="
mount_vol "$V2" --v2-ignore-tags; RC=$?
[ "$RC" -eq 0 ]; check "recovery path unaffected by the new assertion" $?
umount_vol

echo
log "V2 DOWNGRADE: $pass passed, $failc failed"
[ "$failc" -eq 0 ] || { echo "[v2-downgrade] FAILED"; exit 1; }
echo "[v2-downgrade] PASSED"
