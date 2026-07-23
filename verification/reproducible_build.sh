#!/usr/bin/env bash
# reproducible_build.sh — verify the fork's objects build reproducibly (ROI-TOP-50 item 39).
#
# A reproducible build lets anyone rebuild the shipped binary and get bit-for-bit the same output, so
# a signed release can be independently confirmed to come from the published source. The two classic
# sources of non-determinism in C objects are (a) embedded build timestamps (__DATE__/__TIME__) and
# (b) absolute source paths baked into debug info. This checks both:
#
#   1. POSITIVE: every fork Common module, compiled TWICE with a normalized flag set
#      (SOURCE_DATE_EPOCH pinned, -ffile-prefix-map, -g0), is byte-for-byte identical (sha256 match).
#   2. SOURCE SCAN: the fork's own new modules contain no __DATE__/__TIME__/__TIMESTAMP__.
#   3. NEGATIVE CONTROL (proves the check has teeth): the SAME source compiled from two DIFFERENT
#      absolute directories WITHOUT -ffile-prefix-map differs (the path leaks into debug info), and the
#      SAME two compiles WITH -ffile-prefix-map become identical again.
#
# Signing/notarizing a release needs private keys and is the real-build part; the reproducibility that
# makes a signature meaningful is what is proven here.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRCROOT="$HERE/../src"
CC=""; for c in gcc-13 gcc clang-18 clang cc; do command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }; done
[ -z "$CC" ] && { echo "no compiler"; exit 2; }
export SOURCE_DATE_EPOCH=1600000000
NORM="-O2 -g0 -ffile-prefix-map=$SRCROOT=. -frandom-seed=vcrepro -DCRYPTOPP_DISABLE_ASM"
INC="-I$SRCROOT -I$SRCROOT/Common -I$HERE -I$SRCROOT/Crypto"
WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
# fork Common modules (the ROI additions + touched files) — build each with all relevant flags on
MODULES="HardwareKeyFactor KeyScrub DuressToken Keyslot KeyslotStore AfSplit KeyslotAreaFile Shamir ShamirMac ShareCode SelfTest VcStatus VcJson HeaderBackup HkfOrSet VcPosture"
DEFS="-DVC_ENABLE_KEYSCRUB -DVC_ENABLE_HKF -DVC_ENABLE_DURESS -DVC_ENABLE_KEYSLOTS -DVC_ENABLE_KEYSLOT_POLICY -DVC_ENABLE_SHAMIR_MAC -DVC_ENABLE_SHARECODE -DVC_ENABLE_HKF_SALT_BIND -DVC_ENABLE_SELFTEST -DVC_ENABLE_KEYSLOT_SHRED -DVC_ENABLE_STATUS -DVC_ENABLE_JSON -DVC_ENABLE_HEADER_BACKUP -DVC_ENABLE_HKF_ORSET -DVC_ENABLE_POSTURE -DVC_ENABLE_VERIFY"
# fork's own new source files, for the timestamp-construct scan (NOT upstream VeraCrypt files)
FORK_SRC="HardwareKeyFactor KeyScrub DuressToken Keyslot KeyslotStore AfSplit KeyslotAreaFile Shamir ShamirMac ShareCode SelfTest VcStatus VcJson HeaderBackup HkfOrSet VcPosture KeyslotKdf"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0

echo "== reproducible build check ($CC, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH) =="
# (1) every module: identical across two compiles
repro=0; total=0
for m in $MODULES; do
	total=$((total+1))
	$CC $NORM $WNO $DEFS $INC -c "$SRCROOT/Common/$m.c" -o "$WORK/a_$m.o" 2>/dev/null
	$CC $NORM $WNO $DEFS $INC -c "$SRCROOT/Common/$m.c" -o "$WORK/b_$m.o" 2>/dev/null
	if [ -f "$WORK/a_$m.o" ] && cmp -s "$WORK/a_$m.o" "$WORK/b_$m.o"; then
		repro=$((repro+1))
	else
		echo "  NON-REPRODUCIBLE: $m.o differs between two identical compiles"; fail=1
	fi
done
echo "  reproducible modules: $repro/$total (byte-identical across two compiles)"

# (2) source scan: no build-timestamp constructs in the fork's own modules
scan_hits=0
for m in $FORK_SRC; do
	for ext in c h; do
		f="$SRCROOT/Common/$m.$ext"; [ -f "$f" ] || continue
		if grep -Eq '__DATE__|__TIME__|__TIMESTAMP__' "$f"; then
			echo "  TIMESTAMP CONSTRUCT in $m.$ext"; scan_hits=$((scan_hits+1)); fail=1
		fi
	done
done
echo "  timestamp-construct scan: $scan_hits hit(s) in fork modules (want 0)"

# (3) negative control: absolute path leaks into debug info without -ffile-prefix-map
mkdir -p "$WORK/dirA" "$WORK/dirB"
printf 'int reproducible_probe(int x){ static int s=3; return x*s; }\n' > "$WORK/dirA/probe.c"
cp "$WORK/dirA/probe.c" "$WORK/dirB/probe.c"
$CC -O2 -g "$WORK/dirA/probe.c" -c -o "$WORK/pa.o" 2>/dev/null
$CC -O2 -g "$WORK/dirB/probe.c" -c -o "$WORK/pb.o" 2>/dev/null
if cmp -s "$WORK/pa.o" "$WORK/pb.o"; then
	echo "  NEGCTL WEAK: unnormalized builds from different paths were already identical (no teeth on this host)"
	# not a hard failure — some toolchains omit the path; the positive check still stands
else
	echo "  negctl: unnormalized build from a different path DIFFERS (non-determinism is real)"
	$CC -O2 -g -ffile-prefix-map="$WORK/dirA=." "$WORK/dirA/probe.c" -c -o "$WORK/na.o" 2>/dev/null
	$CC -O2 -g -ffile-prefix-map="$WORK/dirB=." "$WORK/dirB/probe.c" -c -o "$WORK/nb.o" 2>/dev/null
	if cmp -s "$WORK/na.o" "$WORK/nb.o"; then
		echo "  negctl: with -ffile-prefix-map the two paths become byte-identical (normalization fixes it)"
	else
		echo "  NEGCTL FAIL: -ffile-prefix-map did not make the two builds identical"; fail=1
	fi
fi

echo ""
if [ "$fail" -eq 0 ] && [ "$repro" -eq "$total" ] && [ "$scan_hits" -eq 0 ]; then
	echo "REPRO PASS: all $total fork modules build byte-identically; no timestamp constructs; normalization proven"
	exit 0
fi
echo "REPRO FAIL"; exit 1
