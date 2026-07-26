#!/bin/bash
# v2_hidden_guard.sh — proves the T1-1 guard: a hidden volume CANNOT be created inside a v2 outer.
#
# WHY THE GUARD EXISTS (this file was v2_hidden_collision.sh, a characterisation test, until the owner
# chose option 1 "mutually exclusive, enforced")
#
# A v2 outer volume reserves its per-sector MAC table at the TAIL of its data area. A hidden volume is
# placed at the TAIL of the outer's data area. They are the same bytes. For a 20 MiB outer with a 5 MiB
# hidden volume the table is [20212736,20840448) and the hidden volume is [15597568,20840448) — the table
# is entirely inside the hidden volume.
#
# The failure mode was not a clean error. Creation looked fine, because VeraCrypt deliberately does not
# wipe the outer's free space, so nothing was written to the table yet. Then the first WRITE to the hidden
# volume overwrote the table, and the outer thereafter opened AS V1 WITH AUTHENTICATION SILENTLY GONE —
# damage deferred past the point of decision, which is when the user could still have chosen otherwise.
#
# Detecting v2 REQUIRES the outer volume's key. A v2 tail is indistinguishable from v1 random free space
# without it — that is the D-10 deniability property working as intended, not an oversight — so there is
# no passwordless probe. Hence --outer-password, and "cannot tell" is treated as "refuse".
#
# WHAT THIS SCRIPT PROVES
#   [1] the overlap is arithmetic, not luck (no build needed for this part);
#   [2] a v2 outer + correct --outer-password  -> REFUSED, naming v2 as the reason;
#   [3] a v1 outer + correct --outer-password  -> ALLOWED (the guard is specific, not a blanket ban);
#   [4] a v2 outer + WRONG   --outer-password  -> REFUSED (fail closed: unverifiable != safe);
#   [5] a v2 outer + no --outer-password, non-interactive -> REFUSED, telling the user what to pass;
#   [6] --skip-v2-host-check bypasses the guard, AND the damage it permits is still real (kept as
#       evidence: the bypass is what keeps the original hazard demonstrable after the guard landed).
#
# [3] is the test that matters most for regressions: a guard that refused everything would pass [2],[4]
# and [5] while breaking every legitimate hidden volume.
#
# ANCHOR CLASS: PROPERTY (fork-specific layout + a policy decision, not a published standard).
# NON-DESTRUCTIVE: file containers inside a mktemp -d. [6]'s write step needs root + /dev/fuse and SKIPs
# without them; every other step runs anywhere the product builds.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VC="$ROOT/src/Main/veracrypt"

log()  { echo "[v2-hidden-guard] $*"; }
fail() { echo "[v2-hidden-guard] FAIL: $*" >&2; exit 1; }

[ -x "$VC" ] || fail "product not built (need scripts/build-product.sh ... V2FORMAT=1)"
"$VC" --help 2>&1 | grep -q -- "--v2-format" || { echo "[v2-hidden-guard] SKIP — built without V2FORMAT=1"; exit 0; }
"$VC" --help 2>&1 | grep -q -- "--outer-password" || fail "V2FORMAT build lacks --outer-password (guard not compiled in)"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
OPW="outer-pw"; HPW="hidden-pw"; OUTER_MB=20; HIDDEN_MB=5

pass=0; failc=0
check() { if [ "$2" = 0 ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; failc=$((failc+1)); fi; return 0; }

mkouter() { # $1=path  $2=extra flags
	"$VC" --text --create "$1" --size=${OUTER_MB}M --password="$OPW" --pim=0 --keyfiles="" \
		--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
		--random-source=/dev/urandom $2 >/dev/null 2>&1
}
mkhidden() { # $1=host  $2..=extra flags; prints combined output, returns the product's exit status
	"$VC" --text --create "$1" --volume-type=hidden --size=${HIDDEN_MB}M --password="$HPW" --pim=0 \
		--keyfiles="" --encryption=AES --hash=SHA-512 --filesystem=none \
		--random-source=/dev/urandom "${@:2}" 2>&1
}

V2="$WORK/v2.hc"; V1="$WORK/v1.hc"
mkouter "$V2" --v2-format || fail "v2 outer create failed"
mkouter "$V1" ""          || fail "v1 outer create failed"

log "=== [1] the overlap is arithmetic ==="
HOST=$(stat -c %s "$V2")
read -r TBLBASE TBLEND HIDSTART <<<"$(python3 - "$HOST" "$HIDDEN_MB" <<'PY'
import sys
host = int(sys.argv[1]); hidden = int(sys.argv[2]) * 1024 * 1024
ss = 512; HDR = 131072
tot_s = (host - 2 * HDR) // ss
u = tot_s
while u + (u * 16 + ss - 1) // ss > tot_s:   # largest U with U + ceil(U*16/ss) <= total sectors
    u -= 1
print(HDR + u * ss, host - HDR, host - HDR - hidden)
PY
)"
log "host=$HOST  outer MAC table=[$TBLBASE,$TBLEND)  hidden volume would be=[$HIDSTART,$TBLEND)"
[ "$HIDSTART" -le "$TBLBASE" ]; check "the outer's MAC table lies entirely inside where a hidden volume goes" $?

log "=== [2] v2 outer + correct outer password -> REFUSED ==="
OUT="$(mkhidden "$V2" --outer-password="$OPW" --outer-pim=0)"; RC=$?
[ "$RC" -ne 0 ]; check "creation is refused (non-zero exit)" $?
echo "$OUT" | grep -q "v2-format volume CANNOT host a hidden volume"; check "the error names v2-format as the reason" $?

log "=== [3] v1 outer + correct outer password -> ALLOWED (guard is specific, not a blanket ban) ==="
OUT="$(mkhidden "$V1" --outer-password="$OPW" --outer-pim=0)"; RC=$?
[ "$RC" -eq 0 ]; check "a hidden volume inside a v1 outer is still permitted" $?
# ...and it must really be usable, not merely "not refused". Uses the FUSE backend (-m nokernelcrypto)
# so the assertion is about the volume opening rather than about which mount backend the box has: this
# box has no /dev/mapper/control, and the kernel dm-crypt path fails here for reasons unrelated to v2.
if [ "$(id -u)" = 0 ] && [ -c /dev/fuse ]; then
	"$VC" --text --mount "$V1" --password="$HPW" --pim=0 --keyfiles="" --protect-hidden=no \
		--filesystem=none --slot=7 -m nokernelcrypto >/dev/null 2>&1
	RC2=$?; "$VC" --text -d --slot=7 >/dev/null 2>&1; sleep 1
	[ "$RC2" -eq 0 ]; check "that hidden volume opens with its own password" $?
else
	echo "  SKIP open-check — needs root + /dev/fuse (creation was still permitted above)"
fi

log "=== [4] v2 outer + WRONG outer password -> REFUSED (fail closed) ==="
OUT="$(mkhidden "$V2" --outer-password="definitely-not-it" --outer-pim=0)"; RC=$?
[ "$RC" -ne 0 ]; check "unverifiable host is refused, not assumed safe" $?
echo "$OUT" | grep -q "not possible to verify"; check "the error says verification was impossible" $?

log "=== [5] v2 outer + no outer password, non-interactive -> REFUSED with instructions ==="
OUT="$(mkhidden "$V2" --non-interactive)"; RC=$?
[ "$RC" -ne 0 ]; check "refused rather than silently skipping the check" $?
echo "$OUT" | grep -q -- "--outer-password"; check "the error tells the user which option to pass" $?

log "=== [6] --skip-v2-host-check bypasses the guard — and the damage is still real ==="
TAG_BEFORE=$(python3 -c "f=open('$V2','rb');f.seek($TBLBASE);print(f.read(16).hex())")
OUT="$(mkhidden "$V2" --skip-v2-host-check)"; RC=$?
[ "$RC" -eq 0 ]; check "the documented bypass still works (recovery/expert escape hatch)" $?

if [ "$(id -u)" = 0 ] && [ -c /dev/fuse ]; then
	"$VC" --text --mount "$V2" --password="$HPW" --pim=0 --keyfiles="" --protect-hidden=no \
		--filesystem=none --slot=7 -m nokernelcrypto >/dev/null 2>&1
	DEV="$("$VC" --text --list -v 2>/dev/null | awk '/Virtual Device/{print $3}' | head -1)"
	if [ -n "$DEV" ] && [ -b "$DEV" ]; then
		dd if=/dev/urandom of="$DEV" bs=1024 count=512 seek=$(( (TBLBASE - HIDSTART) / 1024 )) \
			conv=notrunc status=none 2>/dev/null
		sync; "$VC" --text -d --slot=7 >/dev/null 2>&1; sleep 1
		TAG_AFTER=$(python3 -c "f=open('$V2','rb');f.seek($TBLBASE);print(f.read(16).hex())")
		[ "$TAG_BEFORE" != "$TAG_AFTER" ]; check "writing the bypassed hidden volume overwrites the outer's MAC table" $?

		"$VC" --text --mount "$V2" --password="$OPW" --pim=0 --keyfiles="" --protect-hidden=no \
			--filesystem=none --slot=7 >/dev/null 2>&1
		if "$VC" --text --list -v 2>/dev/null | grep -q "Per-sector authentication: active"; then
			check "the outer then opens WITHOUT authentication (why the guard exists)" 1
		else
			check "the outer then opens WITHOUT authentication (why the guard exists)" 0
		fi
		"$VC" --text -d --slot=7 >/dev/null 2>&1
	else
		echo "  SKIP damage demo — hidden volume exposed no virtual device"
	fi
else
	echo "  SKIP damage demo — needs root + /dev/fuse ([1] already proves the overlap arithmetically)"
fi

echo
log "V2 HIDDEN GUARD: $pass passed, $failc failed"
[ "$failc" -eq 0 ] || { echo "[v2-hidden-guard] FAILED"; exit 1; }
echo "[v2-hidden-guard] PASSED"
