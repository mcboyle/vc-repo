#!/bin/bash
# v2_tamper_e2e.sh — end-to-end proof that v2 per-sector tamper detection is ARMED on a real volume.
#
# WHAT THIS ADDS OVER THE EXISTING TESTS
#   verification/v2_sector_mac_io_test.cpp  proves V2SectorMacIo in isolation (tagging, fail-closed,
#                                           torn-write detection, the override) — 15/15.
#   verification/realbuild/v2_mode_discovery.sh  proves V2FormatDiscoverMode discriminates between the
#                                           two real wide-block EncryptionMode classes.
#   THIS                                    proves the shipping CREATE path and the shipping MOUNT path
#                                           agree, so the layer is actually REACHED on a volume made by
#                                           the product's own CLI.
#
# It exists because the first two were both passing while the feature was off, for three independent
# reasons (the data area was split twice; the backup header was written over the table because nothing
# reserved that region; and mount derived the MAC key from the 256-byte master-key FIELD while create used
# the real 64-byte key). Every one of them ends the same way: discovery returns NONE, the layer stays
# inert, and the volume opens as v1 with authentication absent — silently. A component test cannot see
# that, because each side is self-consistent; only composing create with mount can. See the file header
# of v2_tamper_e2e.cpp for the detail.
#
# NON-DESTRUCTIVE: every volume is a file container inside a mktemp -d. No block device is touched, and
# no kernel dm-crypt is needed (all I/O goes through Volume:: in process), so this runs in a container.
#
# USAGE
#   ./verification/realbuild/v2_tamper_e2e.sh [make feature args]
# Pass the SAME make args used to build the product. Defaults to the minimum set this harness needs.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/src"
: "${CXX:=clang++}"

MAKE_ARGS=("$@")
if [ "${#MAKE_ARGS[@]}" -eq 0 ]; then
	MAKE_ARGS=(NOGUI=1 V2FORMAT=1)
fi

log()  { echo "[v2-tamper-e2e] $*"; }
fail() { echo "[v2-tamper-e2e] FAIL: $*" >&2; exit 1; }

VC="$SRC/Main/veracrypt"
ARCHIVES=("$SRC/Core/Core.a" "$SRC/Volume/Volume.a" "$SRC/Platform/Platform.a")

# --- 1. ensure the product is built -----------------------------------------------------------------
need_build=0
[ -x "$VC" ] || need_build=1
for a in "${ARCHIVES[@]}"; do [ -f "$a" ] || need_build=1; done
if [ "$need_build" = 1 ]; then
	if [ "${VC_OR_SKIP_BUILD:-0}" = 1 ]; then
		fail "product archives/binary missing and VC_OR_SKIP_BUILD=1 (run scripts/build-product.sh ${MAKE_ARGS[*]} first)"
	fi
	log "product not built — building: scripts/build-product.sh ${MAKE_ARGS[*]}"
	"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" || fail "product build failed"
fi

# --- 2. resolve the -D set and refuse a mixed build --------------------------------------------------
# Same guard as open_roundtrip.sh, and for the same reason: a harness compiled with one feature set
# against archives carrying another does not fail to link. It fails as WRONG BEHAVIOUR — here, a volume
# that quietly is not v2 — which is indistinguishable from the very defect this harness exists to catch.
DEFS="$(make -C "$SRC" -pn "${MAKE_ARGS[@]}" 2>/dev/null \
	| grep -E '^C_CXX_FLAGS :?= ' | tail -1 \
	| grep -oE '\-D(VC_ENABLE|TC)_[A-Z_0-9]*' | sort -u | tr '\n' ' ')"
log "feature defs: $DEFS"

case " $DEFS " in
	*" -DVC_ENABLE_V2FORMAT "*) ;;
	*) fail "V2FORMAT is not enabled in these build args — this harness requires V2FORMAT=1";;
esac

STAMP="$SRC/.build-flags"
if [ -f "$STAMP" ]; then
	if [ "$(tr -s ' ' <"$STAMP")" != "$(echo "$DEFS" | tr -s ' ')" ]; then
		log "archive flag stamp: $(cat "$STAMP")"
		log "harness flag set  : $DEFS"
		if [ "${VC_OR_SKIP_BUILD:-0}" = 1 ]; then
			fail "archives were built with a DIFFERENT feature set than requested. Rebuild: scripts/build-product.sh ${MAKE_ARGS[*]}"
		fi
		log "flag-set mismatch — rebuilding the product to match"
		"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" || fail "product rebuild failed"
	fi
else
	log "note: no $STAMP — cannot verify the archives match these defs"
fi

# --- 3. compile + link the harness against the real archives -----------------------------------------
INC="-I$SRC -I$SRC/Crypto -I$SRC/Crypto/Argon2/include -I$SRC/PKCS11"
BASE="-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -DARGON2_NO_THREADS -DTC_ARCH_X64"
BINDIR="$(mktemp -d)"; BIN="$BINDIR/v2_tamper_e2e"
log "compiling harness ($CXX)"
$CXX -O2 -std=c++17 -Wall $BASE $DEFS $INC -c "$HERE/v2_tamper_e2e.cpp" -o "$BIN.o" || fail "harness compile failed"
$CXX -o "$BIN" "$BIN.o" \
	-Wl,--start-group "${ARCHIVES[@]}" -Wl,--end-group \
	$(pkg-config fuse --libs 2>/dev/null || pkg-config fuse3 --libs 2>/dev/null) \
	$(wx-config --libs base 2>/dev/null) -lpthread || fail "harness link failed"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "$BINDIR"' EXIT
export VC_OPEN_KDF="HMAC-SHA-512"        # volumes are created --hash=SHA-512; pin it so opens stay fast
PW="v2-tamper-e2e-pw"

pass=0; failc=0
check() { # $1=label  $2=expected-exit  $3..=harness argv
	local label="$1" want="$2"; shift 2
	timeout 180 "$BIN" "$@" >"$WORK/h.out" 2>&1; local rc=$?
	if [ "$rc" = "$want" ]; then
		echo "  ok   $label"; pass=$((pass+1))
		[ -s "$WORK/h.out" ] && sed 's/^/         /' "$WORK/h.out"
	else
		echo "  FAIL $label (exit $rc, wanted $want)"; sed 's/^/       /' "$WORK/h.out"; failc=$((failc+1))
	fi
	return 0
}

mkvol() { # $1=path  $2..=extra create flags
	local v="$1"; shift
	"$VC" --text --create "$v" --size=10M --password="$PW" --pim=0 --keyfiles="" \
		--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
		--random-source=/dev/urandom "$@" >"$WORK/create.log" 2>&1
}

V2="$WORK/v2.hc"
V1="$WORK/v1.hc"
SECTOR=7

log "=== creating volumes ==="
mkvol "$V2" --v2-format || fail "v2 create failed: $(tail -3 "$WORK/create.log")"
mkvol "$V1"             || fail "v1 create failed: $(tail -3 "$WORK/create.log")"
log "created $V2 (v2) and $V1 (v1 control)"

# --- 4a. THE LOAD-BEARING ASSERTION -----------------------------------------------------------------
# Everything below is conditional on this. If the mount path does not recognise the volume as v2, then a
# later "the read was refused" can never happen and a later "the read succeeded" proves nothing — the
# whole suite would pass vacuously in exactly the configuration the feature is broken in.
log "=== [1] the mount path recognises a --v2-format volume ==="
check "a --v2-format volume opens AS V2 (create and mount agree on the table offset)" 0 probe "$V2" "$PW"
check "a stock volume does NOT open as v2 (no false positives; v1 path unchanged)"    0 not_v2 "$V1" "$PW"

# --- 4b. authenticated I/O round-trips ---------------------------------------------------------------
log "=== [2] authenticated read/write round-trip ==="
check "write a known sector through the authenticated path"  0 write "$V2" "$PW" "$SECTOR" 0xA5
check "read it back intact (tags were written AND verified)" 0 read  "$V2" "$PW" "$SECTOR" 0xA5

# Write a second, known sector too — it is the control for the "failure is per-sector" check below.
# It has to be WRITTEN, not just assumed: the format pass fills the data area with sectors encrypted
# under a throwaway key, so an unwritten sector decrypts to garbage under the master key. Asserting it
# reads as zeroes fails for a reason that has nothing to do with tamper detection.
check "write a second known sector (the control for per-sector scoping)" 0 write "$V2" "$PW" 0 0x3C
check "and it reads back intact"                                         0 read  "$V2" "$PW" 0 0x3C

# The v1 control must round-trip identically — the layer is a no-op on non-v2 volumes.
check "v1 control: write still works"     0 write "$V1" "$PW" "$SECTOR" 0x5A
check "v1 control: read still round-trips" 0 read  "$V1" "$PW" "$SECTOR" 0x5A

# --- 4c. tamper, and require the refusal -------------------------------------------------------------
log "=== [3] tamper detection: fail closed ==="
check "flip one bit of ciphertext on disk (outside the volume abstraction)" 0 tamper "$V2" "$PW" "$SECTOR"
check "reading the tampered sector is REFUSED — no plaintext returned"      0 read_refuse "$V2" "$PW" "$SECTOR"

# An untouched sector must still be readable: the refusal is per-sector, not per-volume. Without this a
# fail-closed layer that simply broke every read would look identical to one that works.
check "a DIFFERENT, untouched sector still reads (failure is scoped to the damaged sector)" \
	0 read "$V2" "$PW" 0 0x3C

# --- 4d. the recovery path ---------------------------------------------------------------------------
# Fail-closed without recovery turns one bad sector into a lost volume, so the override is a requirement
# (docs/V2-FORMAT-SPEC.md). Assert both halves: it lets the read through, AND it records that it did.
log "=== [4] the operator override (the mandatory recovery path) ==="
check "with the override the read proceeds, and the ignore is COUNTED" 0 read_override "$V2" "$PW" "$SECTOR"

# The override is per-instance and never persisted; a fresh open must fail closed again. If it did not,
# an adversary who could set it once would have disabled detection permanently.
check "a FRESH open fails closed again (the override is not persisted to the volume)" \
	0 read_refuse "$V2" "$PW" "$SECTOR"

# --- 5. THROUGH THE REAL CLI, ON A REAL MOUNT --------------------------------------------------------
# Sections 1-4 drive Volume:: in process. That proves the layer works, but NOT that a user can reach it:
# the override lives in MountOptions, crosses a fork into the FUSE service (where reads actually happen),
# and the resulting count has to travel BACK through VolumeInfo serialization to be printed. Any link in
# that chain could break silently — most quietly of all the serialization, which would report "0 sectors
# ignored" forever while the override worked fine. Since the override is only permitted to exist because
# it is LOGGED (docs/V2-FORMAT-SPEC.md, requirement 2), a count that never arrives is a policy failure,
# not a cosmetic one. So drive the actual CLI.
#
# Self-gating: needs root, /dev/fuse, and loop devices. Prints SKIP rather than FAIL without them.
checksh() { # $1=label  $2=0|1 expected success  $3..=command
	local label="$1" want="$2"; shift 2
	if "$@" >"$WORK/c.out" 2>&1; then local rc=0; else local rc=1; fi
	if [ "$rc" = "$want" ]; then echo "  ok   $label"; pass=$((pass+1))
	else echo "  FAIL $label (rc $rc, wanted $want)"; sed 's/^/       /' "$WORK/c.out"; failc=$((failc+1)); fi
	return 0
}

SLOT=9
props() { "$VC" --text --list -v 2>/dev/null | awk -v RS='' -v p="$1" 'index($0,p)'; }
dismount_slot() { "$VC" --text -d --slot="$SLOT" >/dev/null 2>&1 || true; sleep 1; }

if [ "$(id -u)" = 0 ] && [ -c /dev/fuse ]; then
	log "=== [5] through the real CLI on a real mount ==="
	trap 'dismount_slot; rm -rf "$WORK" "$BINDIR"' EXIT

	CLIVOL="$WORK/cli.hc"
	mkvol "$CLIVOL" --v2-format || fail "cli v2 create failed: $(tail -3 "$WORK/create.log")"

	mountv2() { # $@ = extra flags
		"$VC" --text --mount "$CLIVOL" --password="$PW" --pim=0 --keyfiles="" \
			--protect-hidden=no --filesystem=none --slot="$SLOT" "$@"
	}

	# Write a known sector through the authenticated path, so the tag on disk is a REAL tag over data we
	# put there — not format-pass filler whose tag would also verify but prove less.
	if mountv2 >"$WORK/m.log" 2>&1; then
		DEV="$(props "$CLIVOL" | awk '/Virtual Device/ {print $3}')"
		if [ -n "$DEV" ] && [ -b "$DEV" ]; then
			tr '\0' '\245' </dev/zero | dd of="$DEV" bs=512 count=1 seek="$SECTOR" conv=notrunc status=none
			sync
			dismount_slot

			checksh "tamper one ciphertext bit of that sector on disk" 0 "$BIN" tamper "$CLIVOL" "$PW" "$SECTOR"

			# --- A. default mount: the refusal must reach the BLOCK DEVICE, not just the C++ API -------
			mountv2 >"$WORK/m.log" 2>&1
			checksh "default mount: reading the tampered sector fails (fail-closed reaches the device)" \
				1 dd if="$DEV" of=/dev/null bs=512 count=1 skip="$SECTOR" status=none
			checksh "...and --list -v reports authentication ACTIVE" 0 \
				bash -c "props() { \"$VC\" --text --list -v 2>/dev/null | awk -v RS='' -v p=\"$CLIVOL\" 'index(\$0,p)'; }; props | grep -q 'Per-sector authentication: active'"
			checksh "...and reports NO ignored sectors (nothing was silently let through)" 1 \
				bash -c "\"$VC\" --text --list -v 2>/dev/null | grep -q 'WITHOUT valid authentication'"
			dismount_slot

			# --- B. --v2-ignore-tags: the recovery path, and the logging that justifies it -------------
			mountv2 --v2-ignore-tags >"$WORK/m.log" 2>&1
			checksh "--v2-ignore-tags warns at mount time that authentication is disabled" 0 \
				grep -q "authentication is DISABLED" "$WORK/m.log"
			checksh "--v2-ignore-tags: the tampered sector now READS (recovery works)" \
				0 dd if="$DEV" of=/dev/null bs=512 count=1 skip="$SECTOR" status=none
			# THE LOAD-BEARING ONE: the count is produced in the forked FUSE process and must survive
			# VolumeInfo serialization to get here. Without it the override is unlogged = fail-warn.
			checksh "...and --list -v reports the ignored sector, with its index (count crossed the fork)" 0 \
				bash -c "\"$VC\" --text --list -v 2>/dev/null | grep -q '1 sector(s) returned WITHOUT valid authentication; first at sector $SECTOR'"
			dismount_slot
		else
			skipmsg="virtual device not exposed (got '${DEV:-none}')"
			echo "  SKIP real-CLI mount tier — $skipmsg"
			dismount_slot
		fi
	else
		echo "  SKIP real-CLI mount tier — mount failed: $(tail -1 "$WORK/m.log")"
	fi
else
	echo "  SKIP real-CLI mount tier — needs root + /dev/fuse (in-process tiers above still ran)"
fi

# --- 6. tally ----------------------------------------------------------------------------------------
echo
log "V2 TAMPER E2E: $pass passed, $failc failed"
[ "$failc" -eq 0 ] || { echo "[v2-tamper-e2e] FAILED"; exit 1; }
echo "[v2-tamper-e2e] PASSED"
