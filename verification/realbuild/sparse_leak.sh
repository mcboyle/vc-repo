#!/bin/bash
# sparse_leak.sh — a sparse container discloses its hidden volume with NO password, from ONE image.
#
# THE LEAK
#
# A file container created with --quick is sized by ftruncate, so the host filesystem records it as
# mostly HOLE: only the two 128 KiB header regions are allocated. Writing to a hidden volume inside it
# allocates blocks EXACTLY where the hidden volume lives. The resulting extent map is host filesystem
# metadata about the container, readable by anyone holding the file, and it discloses both the hidden
# volume's offset and how much of it has been written.
#
# Measured on ext4 (step [2] below reproduces it):
#     20 MiB --quick outer, before:  DATA [0,131072)  [20840448,20971520)          <- headers only
#     after creating a 5 MiB hidden volume and writing 2 MiB to it:
#                                    DATA [0,131072)  [15597568,17694720)  [20840448,20971520)
#     the middle extent begins at 15597568 = exactly the hidden volume's start offset.
#
# WHY THIS MATTERS MORE THAN THE THREAT MODEL'S HEADLINE LIMITATION
#
# docs/THREAT-MODEL.md names the MULTI-SNAPSHOT adversary as the principal limit on hidden-volume
# deniability: someone who images the medium twice and diffs. This is STRICTLY STRONGER — it needs ONE
# image and no password — and encryption cannot defend against it, because nothing about the leak is
# inside the volume. It is the filesystem talking about the container.
#
# WHAT ALREADY EXISTED, AND WHAT THIS ADDS
#
# The fork ALREADY warns at outer-creation time (TextUserInterface.cpp): "Do not use --quick for an
# outer volume intended to contain a hidden volume... For file containers, actual disk savings depend on
# host filesystem sparse-file support". That warning is accurate and it names the right mechanism. What
# it cannot do is bind: it fires when the OUTER volume is created, which may be months before anyone
# decides to put a hidden volume inside, and it is advisory. This adds the mechanical check at the point
# where the decision is actually being made.
#
# WHAT THIS SCRIPT PROVES
#   [1] a --quick container really is sparse (allocated blocks << apparent size);
#   [2] THE LEAK, end to end: create hidden, write to it, recover its offset with no password;
#   [3] the guard refuses a hidden volume inside a sparse host, and explains why;
#   [4] specificity: a fully-allocated host still accepts a hidden volume;
#   [5] --allow-sparse-host overrides, so recovery/expert use is not blocked.
#
# [4] is the regression-critical one: a guard that refused every host would pass [3] and be useless.
#
# ANCHOR CLASS: THIRD-PARTY MECHANISM. The extent map is produced by the Linux kernel and ext4, not by
# anything we wrote; SEEK_HOLE/SEEK_DATA is the kernel's own interface. The fork-specific policy (refuse)
# is [TWIN-ONLY].
# NON-DESTRUCTIVE: file containers inside a mktemp -d.
# NOTE: deliberately no pipefail. Every create below is driven as `yes y | veracrypt ...` to answer
# the --quick confirmation prompt, and `yes` always dies of SIGPIPE when veracrypt exits — under
# pipefail that turns every successful create into a reported failure. Without it the pipeline yields
# veracrypt's own status, which is exactly what these checks want.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VC="$ROOT/src/Main/veracrypt"

log()  { echo "[sparse-leak] $*"; }
fail() { echo "[sparse-leak] FAIL: $*" >&2; exit 1; }

[ -x "$VC" ] || fail "product not built"
"$VC" --help 2>&1 | grep -q -- "--allow-sparse-host" || { echo "[sparse-leak] SKIP — built without SPARSE_GUARD=1"; exit 0; }
"$VC" --help 2>&1 | grep -q -- "--outer-password"    || fail "needs V2FORMAT=1 too (--outer-password drives hidden creation)"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
OPW="outer-pw"; HPW="hidden-pw"

pass=0; failc=0
check() { if [ "$2" = 0 ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; failc=$((failc+1)); fi; return 0; }

extents() { python3 - "$1" <<'PY'
import os,sys
f=os.open(sys.argv[1],os.O_RDONLY); sz=os.lseek(f,0,os.SEEK_END); off=0; out=[]
while off<sz:
    try: d=os.lseek(f,off,os.SEEK_DATA)
    except OSError: break
    try: h=os.lseek(f,d,os.SEEK_HOLE)
    except OSError: h=sz
    out.append((d,h)); off=h
os.close(f)
print(" ".join("%d:%d"%(a,b) for a,b in out))
PY
}
# extents that are neither the primary nor the backup header region == the hidden volume's footprint
midextents() { python3 - "$1" <<'PY'
import os,sys
HDR=131072
f=os.open(sys.argv[1],os.O_RDONLY); sz=os.lseek(f,0,os.SEEK_END); off=0; out=[]
while off<sz:
    try: d=os.lseek(f,off,os.SEEK_DATA)
    except OSError: break
    try: h=os.lseek(f,d,os.SEEK_HOLE)
    except OSError: h=sz
    if d>=HDR and h<=sz-HDR: out.append((d,h))
    off=h
os.close(f)
print(" ".join("%d:%d"%(a,b) for a,b in out))
PY
}

mkouter() { yes y | "$VC" --text --create "$1" --size=20M --password="$OPW" --pim=0 --keyfiles="" \
	--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
	--random-source=/dev/urandom $2 >/dev/null 2>&1; }
mkhidden() { yes y | "$VC" --text --create "$1" --volume-type=hidden --size=5M --password="$HPW" --pim=0 \
	--keyfiles="" --encryption=AES --hash=SHA-512 --filesystem=none --random-source=/dev/urandom \
	--outer-password="$OPW" --outer-pim=0 "${@:2}" 2>&1; }

SPARSE="$WORK/sparse.hc"; FULL="$WORK/full.hc"; LEAK="$WORK/leak.hc"
mkouter "$SPARSE" --quick || fail "sparse outer create failed"
mkouter "$FULL"   ""      || fail "full outer create failed"

log "=== [1] a --quick container is sparse ==="
SB=$(stat -c %b "$SPARSE"); FB=$(stat -c %b "$FULL"); AP=$(stat -c %s "$SPARSE")
log "apparent=$AP  sparse-allocated=${SB} blocks  fully-allocated=${FB} blocks (512B units)"
[ "$SB" -lt $((FB / 4)) ]; check "the --quick container allocates far fewer blocks than its apparent size" $?
log "extents: $(extents "$SPARSE")"
[ -z "$(midextents "$SPARSE")" ]; check "before any hidden volume, only the header regions are allocated" $?

log "=== [2] THE LEAK — recover the hidden volume's offset with no password ==="
if [ "$(id -u)" = 0 ] && [ -c /dev/fuse ]; then
	mkouter "$LEAK" --quick || fail "leak-fixture outer create failed"
	mkhidden "$LEAK" --allow-sparse-host >/dev/null 2>&1
	"$VC" --text --mount "$LEAK" --password="$HPW" --pim=0 --keyfiles="" --protect-hidden=no \
		--filesystem=none --slot=7 -m nokernelcrypto >/dev/null 2>&1
	DEV="$("$VC" --text --list -v 2>/dev/null | awk '/Virtual Device/{print $3}' | head -1)"
	if [ -n "$DEV" ] && [ -b "$DEV" ]; then
		dd if=/dev/urandom of="$DEV" bs=1M count=2 conv=notrunc status=none 2>/dev/null; sync
		"$VC" --text -d --slot=7 >/dev/null 2>&1; sleep 1
		MID="$(midextents "$LEAK")"
		log "extents after writing: $(extents "$LEAK")"
		log "hidden-volume footprint recovered WITHOUT a password: ${MID:-<none>}"
		[ -n "$MID" ]; check "the extent map discloses the hidden volume (this is the leak)" $?
	else
		echo "  SKIP leak demo — hidden volume exposed no virtual device"
		"$VC" --text -d --slot=7 >/dev/null 2>&1
	fi
else
	echo "  SKIP leak demo — needs root + /dev/fuse ([1] already shows the container is sparse)"
fi

log "=== [3] the guard refuses a hidden volume inside a sparse host ==="
OUT="$(mkhidden "$SPARSE")"; RC=$?
[ "$RC" -ne 0 ]; check "creation is refused" $?
echo "$OUT" | grep -q "SPARSE file"; check "the error names sparseness as the cause" $?
echo "$OUT" | grep -q "NO password"; check "the error states the leak needs no password" $?
echo "$OUT" | grep -q "fallocate"; check "the error tells the user how to fix it" $?

log "=== [4] specificity — a fully-allocated host still accepts a hidden volume ==="
OUT="$(mkhidden "$FULL")"; RC=$?
[ "$RC" -eq 0 ]; check "hidden volume permitted inside a non-sparse host" $?
[ -n "$(midextents "$FULL")" ] || true   # informational: a full host has no hole structure to read

log "=== [5] --allow-sparse-host overrides ==="
OUT="$(mkhidden "$SPARSE" --allow-sparse-host)"; RC=$?
[ "$RC" -eq 0 ]; check "the documented override still works" $?

echo
log "SPARSE LEAK: $pass passed, $failc failed"
[ "$failc" -eq 0 ] || { echo "[sparse-leak] FAILED"; exit 1; }
echo "[sparse-leak] PASSED"
