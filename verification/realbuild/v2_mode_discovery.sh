#!/bin/bash
# v2_mode_discovery.sh — build + run the V2 mode-discovery harness against the real product objects.
#
# WHY THIS IS realbuild-TIER, NOT A SELF-CONTAINED SUITE STEP
# It links the real Volume.a/Core.a/Platform.a because it drives the ACTUAL EncryptionModeHctr2 and
# EncryptionModeAdiantum classes rather than stand-ins — the whole point is that two REAL wide-block
# modes produce two real ciphertexts and discovery picks correctly between them. A step that links
# product archives can only ever skip_step inside build_and_verify.sh, and --strict fails on a skip;
# that tier mistake already cost PR #35 a red CI run.
#
# WHAT IT PROVES (T1-1, the discovery half)
# V2FormatDiscoverMode identifies a volume's wide-block mode by deriving each mode's MAC key from the
# master key and testing which reproduces the stored sector-0 tag. Step [85] proved that tag arithmetic
# against a twin — but with only ONE wide-block EncryptionMode implemented, DISCRIMINATION could never
# be exercised: you could show NONE for a wrong key and nothing more. EncryptionModeHctr2 makes the
# real question answerable for the first time.
#
# WHAT IT DOES NOT PROVE, stated so nobody reads more into a green run: this is discovery only. It does
# not exercise the per-sector MAC I/O layer (tags are computed here, not written through
# Volume::WriteSectors), and it takes no position on fail-closed vs fail-warn when a tag mismatches on a
# real read — that is an owner-gated policy decision, not a fact about this code.
#
# Usage: bash verification/realbuild/v2_mode_discovery.sh [make feature args]
# VC_V2_SKIP_BUILD=1 requires the archives to exist already.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/src"
: "${CXX:=clang++}"
: "${CC:=clang}"

MAKE_ARGS=("$@")
[ "${#MAKE_ARGS[@]}" -eq 0 ] && MAKE_ARGS=(NOGUI=1 HCTR2_MODE=1 ADIANTUM_MODE=1 V2FORMAT=1)

log()  { echo "[v2-discovery] $*"; }
fail() { echo "[v2-discovery] FAIL: $*" >&2; exit 1; }

ARCHIVES=("$SRC/Volume/Volume.a" "$SRC/Core/Core.a" "$SRC/Platform/Platform.a")
need=0; for a in "${ARCHIVES[@]}"; do [ -f "$a" ] || need=1; done
if [ "$need" = 1 ]; then
	[ "${VC_V2_SKIP_BUILD:-0}" = 1 ] && fail "product archives missing and VC_V2_SKIP_BUILD=1"
	log "archives missing — building: scripts/build-product.sh ${MAKE_ARGS[*]}"
	"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" >/tmp/v2d_build.log 2>&1 \
		|| fail "product build failed (see /tmp/v2d_build.log)"
fi

D="-DVC_ENABLE_HCTR2 -DVC_ENABLE_HCTR2_MODE -DVC_ENABLE_ADIANTUM -DVC_ENABLE_ADIANTUM_MODE"
D="$D -DVC_ENABLE_CTAES -DVC_ENABLE_POLY1305 -DVC_ENABLE_V2FORMAT"
NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
INC="-I$SRC -I$SRC/Common -I$SRC/Crypto -I$SRC/PKCS11 -I$SRC/Crypto/Argon2/include"
BASE="-DTC_UNIX -DTC_LINUX -D_FILE_OFFSET_BITS=64 -DARGON2_NO_THREADS"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

log "compiling the crypto + format objects"
for f in Hctr2 AesCt Adiantum chacha256 Poly1305; do
	$CC -O2 $D $NOASM $INC -c "$SRC/Crypto/$f.c" -o "$WORK/$f.o" 2>>"$WORK/cc.log" \
		|| fail "could not compile Crypto/$f.c (see $WORK/cc.log)"
done
$CC -O2 $D $NOASM $INC -c "$SRC/Crypto/Sha2.c" -o "$WORK/Sha2.o" 2>>"$WORK/cc.log" \
	|| fail "could not compile Crypto/Sha2.c"
$CC -O2 $D $NOASM $INC -c "$SRC/Common/V2Format.c" -o "$WORK/V2Format.o" 2>>"$WORK/cc.log" \
	|| fail "could not compile Common/V2Format.c"

# The two mode shims are compiled HERE rather than taken from Volume.a: the archive only carries them
# when the product was built with both flags, and this test must not silently pass by linking a stale
# object (or fail confusingly when a flag was absent).
log "compiling both EncryptionMode shims + the test"
$CXX -O2 -std=c++17 $D $NOASM $BASE $INC -Wall -c "$SRC/Volume/EncryptionModeHctr2.cpp" -o "$WORK/mh.o" \
	2>>"$WORK/cc.log" || fail "could not compile EncryptionModeHctr2.cpp (see $WORK/cc.log)"
$CXX -O2 -std=c++17 $D $NOASM $BASE $INC -Wall -c "$SRC/Volume/EncryptionModeAdiantum.cpp" -o "$WORK/ma.o" \
	2>>"$WORK/cc.log" || fail "could not compile EncryptionModeAdiantum.cpp (see $WORK/cc.log)"
$CXX -O2 -std=c++17 $D $NOASM $BASE $INC -Wall -c "$HERE/../v2_mode_discovery_test.cpp" -o "$WORK/t.o" \
	2>>"$WORK/cc.log" || fail "could not compile v2_mode_discovery_test.cpp (see $WORK/cc.log)"

log "linking against the real product archives"
$CXX -o "$WORK/run" "$WORK/t.o" "$WORK/mh.o" "$WORK/ma.o" \
	"$WORK"/Hctr2.o "$WORK"/AesCt.o "$WORK"/Adiantum.o "$WORK"/chacha256.o "$WORK"/Poly1305.o \
	"$WORK"/V2Format.o "$WORK"/Sha2.o \
	-Wl,--start-group "${ARCHIVES[@]}" -Wl,--end-group \
	$(pkg-config fuse --libs 2>/dev/null) $(wx-config --libs base 2>/dev/null) -lpthread \
	2>>"$WORK/cc.log" || fail "link failed (see $WORK/cc.log)"

"$WORK/run" | sed 's/^/  /'
rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] || fail "the V2 mode-discovery test failed (exit $rc)"
log "PASS — mode discovery discriminates between two REAL wide-block EncryptionMode classes"
