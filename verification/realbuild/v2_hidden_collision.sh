#!/bin/bash
# v2_hidden_collision.sh — demonstrates that a v2 (authenticated) OUTER volume and a hidden volume
# occupy the SAME BYTES, and that using the hidden volume destroys the outer's authentication.
#
# WHY THIS EXISTS
# docs/V2-FORMAT-SPEC.md §"The resolution of the tension" claims the two coexist safely:
#
#     "On reading a sector whose MAC does not verify, v2 treats it as uninitialised / free, exactly as
#      v1 treats random free space — it is NOT flagged as tampering. ... the outer sees those sectors as
#      'MAC-mismatch = free' — the SAME view v1 gives of random free space. => no new tell."
#
# THAT RESOLUTION DOES NOT SURVIVE THE POLICY THAT ACTUALLY SHIPPED. The owner decided FAIL CLOSED
# (2026-07-25): a tag mismatch REFUSES the read and returns no data. "Mismatch = free space" and
# "mismatch = refuse" are opposite behaviours, and the deniability argument depends on the first one.
# The spec was written before the policy was chosen and was never reconciled with it.
#
# THE COLLISION IS STRUCTURAL, not a bug in the MAC layer:
#   - the MAC table is placed at the TAIL of the outer's data area (V2FormatSplitDataArea);
#   - a hidden volume is placed at the TAIL of the outer's data area (that is what makes it hidden).
# They are the same region. For a 20 MiB outer with a 5 MiB hidden volume the outer's table occupies
# [20212736, 20840448) and the hidden volume occupies [15597568, 20840448) — the table is entirely
# inside the hidden volume.
#
# WHAT THIS SCRIPT SHOWS, in order:
#   1. a v2 outer volume opens as v2 (authentication active);
#   2. creating a hidden volume inside it does NOT yet damage the table — VeraCrypt deliberately does
#      not wipe the outer's free space, so nothing is written there yet and everything still looks fine;
#   3. WRITING to the hidden volume overwrites the outer's MAC table;
#   4. the outer then opens as v1 — authentication silently GONE.
#
# Step 2 matters as much as step 4: the damage is invisible at creation time and only appears once the
# hidden volume is used, which is exactly when the user is least able to notice.
#
# ANCHOR CLASS: PROPERTY. This asserts a structural collision in fork-specific layout, not conformance.
#
# NON-DESTRUCTIVE: file containers inside a mktemp -d. Needs root + /dev/fuse to write to the hidden
# volume; without them it still proves the overlap arithmetically and SKIPs the write step.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/src"
VC="$SRC/Main/veracrypt"

log()  { echo "[v2-hidden] $*"; }
fail() { echo "[v2-hidden] FAIL: $*" >&2; exit 1; }

[ -x "$VC" ] || fail "product not built (need scripts/build-product.sh ... V2FORMAT=1)"
"$VC" --help 2>&1 | grep -q -- "--v2-format" || { echo "[v2-hidden] SKIP — built without V2FORMAT=1"; exit 0; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
OUTER="$WORK/outer.hc"
OPW="outer-pw"; HPW="hidden-pw"
OUTER_MB=20; HIDDEN_MB=5

pass=0; failc=0
check() { if [ "$2" = 0 ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; failc=$((failc+1)); fi; return 0; }

log "=== [1] create a v2 outer volume ==="
"$VC" --text --create "$OUTER" --size=${OUTER_MB}M --password="$OPW" --pim=0 --keyfiles="" \
	--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
	--random-source=/dev/urandom --v2-format >"$WORK/c.log" 2>&1 || fail "outer create failed"

HOST=$(stat -c %s "$OUTER")
# Same arithmetic the product uses: usable prefix + table = the whole data area.
read -r USABLE TBLBASE TBLEND HIDSTART <<<"$(python3 - "$HOST" "$HIDDEN_MB" <<'PY'
import sys
host = int(sys.argv[1]); hidden = int(sys.argv[2]) * 1024 * 1024
ss = 512; HDR = 131072
total = host - 2 * HDR                      # data area between the header groups
tot_s = total // ss
u = tot_s
while u + (u * 16 + ss - 1) // ss > tot_s:  # largest U with U + ceil(U*16/ss) <= total sectors
    u -= 1
usable = u * ss
print(HDR + usable - HDR + HDR, HDR + usable, host - HDR, host - HDR - hidden)
PY
)"
log "host=$HOST  outer MAC table=[$TBLBASE,$TBLEND)  hidden volume=[$HIDSTART,$TBLEND)"

# The overlap is arithmetic, not luck: assert it rather than assuming it.
[ "$HIDSTART" -le "$TBLBASE" ] && OVL=0 || OVL=1
check "the outer's MAC table lies ENTIRELY inside where the hidden volume goes" "$OVL"

TAG_BEFORE=$(python3 -c "f=open('$OUTER','rb');f.seek($TBLBASE);print(f.read(16).hex())")

log "=== [2] the outer is authenticated ==="
"$VC" --text --mount "$OUTER" --password="$OPW" --pim=0 --keyfiles="" --protect-hidden=no \
	--filesystem=none --slot=7 >/dev/null 2>&1
"$VC" --text --list -v 2>/dev/null | grep -q "Per-sector authentication: active"; check "outer reports authentication ACTIVE" $?
"$VC" --text -d --slot=7 >/dev/null 2>&1; sleep 1

log "=== [3] create a hidden volume inside it ==="
"$VC" --text --create "$OUTER" --volume-type=hidden --size=${HIDDEN_MB}M --password="$HPW" --pim=0 \
	--keyfiles="" --encryption=AES --hash=SHA-512 --filesystem=none \
	--random-source=/dev/urandom >"$WORK/h.log" 2>&1 || fail "hidden create failed"

# NOTHING refuses the combination today. Recording that explicitly: the product lets a user build a
# configuration in which the two features destroy each other, with no warning at the point of decision.
check "the product ACCEPTS a hidden volume inside a v2 outer (no guard exists)" 0

TAG_AFTER_CREATE=$(python3 -c "f=open('$OUTER','rb');f.seek($TBLBASE);print(f.read(16).hex())")
[ "$TAG_BEFORE" = "$TAG_AFTER_CREATE" ]; check "creation alone does NOT yet damage the table (damage is deferred, and so invisible)" $?

log "=== [4] WRITE to the hidden volume — this is what destroys the outer ==="
if [ "$(id -u)" = 0 ] && [ -c /dev/fuse ]; then
	"$VC" --text --mount "$OUTER" --password="$HPW" --pim=0 --keyfiles="" --protect-hidden=no \
		--filesystem=none --slot=7 -m nokernelcrypto >/dev/null 2>&1
	DEV="$("$VC" --text --list -v 2>/dev/null | awk '/Virtual Device/{print $3}' | head -1)"
	if [ -n "$DEV" ] && [ -b "$DEV" ]; then
		OFF=$(( TBLBASE - HIDSTART ))       # the offset inside the hidden volume that lands on the table
		dd if=/dev/urandom of="$DEV" bs=1024 count=512 seek=$((OFF/1024)) conv=notrunc status=none 2>/dev/null
		sync; "$VC" --text -d --slot=7 >/dev/null 2>&1; sleep 1

		TAG_AFTER_WRITE=$(python3 -c "f=open('$OUTER','rb');f.seek($TBLBASE);print(f.read(16).hex())")
		[ "$TAG_BEFORE" != "$TAG_AFTER_WRITE" ]; check "using the hidden volume OVERWRITES the outer's MAC table" $?

		# The consequence, and the reason this is a security finding rather than a corruption bug: the
		# outer volume still mounts perfectly well — it just is not authenticated any more, and says so
		# nowhere. Same silent-absence shape as the defects fixed in #40/#41.
		"$VC" --text --mount "$OUTER" --password="$OPW" --pim=0 --keyfiles="" --protect-hidden=no \
			--filesystem=none --slot=7 >/dev/null 2>&1
		if "$VC" --text --list -v 2>/dev/null | grep -q "Per-sector authentication: active"; then
			check "outer now opens WITHOUT authentication (silent loss)" 1
		else
			check "outer now opens WITHOUT authentication (silent loss) — CONFIRMED" 0
		fi
		"$VC" --text -d --slot=7 >/dev/null 2>&1
	else
		echo "  SKIP write step — hidden volume exposed no virtual device"
	fi
else
	echo "  SKIP write step — needs root + /dev/fuse (the overlap above is already proven arithmetically)"
fi

echo
log "V2 HIDDEN COLLISION: $pass passed, $failc failed"
[ "$failc" -eq 0 ] || { echo "[v2-hidden] FAILED"; exit 1; }
echo "[v2-hidden] PASSED — the collision is reproduced and characterised"
