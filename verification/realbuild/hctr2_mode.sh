#!/bin/bash
# hctr2_mode.sh — build + run the EncryptionModeHctr2 shim test against the real product objects.
#
# WHY THIS LIVES IN realbuild/ AND NOT IN build_and_verify.sh
# The self-contained suite compiles Common/Crypto objects individually and needs no VeraCrypt build —
# that is its contract (CLAUDE.md: "Self-contained checks (no VeraCrypt build needed)"). This test links
# the real Volume.a/Core.a/Platform.a, because the whole point is to exercise the ACTUAL EncryptionMode
# base class rather than a stand-in. That makes it a realbuild-tier test, alongside open_roundtrip.sh and
# netshare_cli.sh.
#
# It was briefly step [103] in the self-contained suite, where it could only ever skip_step for want of
# archives — and under --strict a skip is a failure, so it turned a green suite red. The tier was the
# bug, not the test.
#
# WHAT IT ASSERTS
# Step [91] proves the Hctr2 ALGORITHM against all 18 official google/hctr2 KATs. This proves the
# SHIM: integration faults the KATs cannot see — tweak convention, SectorOffset participation,
# sector/data-unit confusion, in-place aliasing. The load-bearing one is WIDE-BLOCK DIFFUSION: flip one
# plaintext bit and the whole sector must change (XTS changes 16 bytes). That is the entire reason to
# prefer Hctr2 here and precisely what a bad shim silently loses.
#
# Usage: bash verification/realbuild/hctr2_mode.sh [make feature args]
# Builds the product with HCTR2_MODE=1 if the archives are absent; VC_H2_SKIP_BUILD=1 requires them.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/src"
: "${CXX:=clang++}"
: "${CC:=clang}"

MAKE_ARGS=("$@")
[ "${#MAKE_ARGS[@]}" -eq 0 ] && MAKE_ARGS=(NOGUI=1 HCTR2_MODE=1)

log()  { echo "[hctr2-mode] $*"; }
fail() { echo "[hctr2-mode] FAIL: $*" >&2; exit 1; }

ARCHIVES=("$SRC/Volume/Volume.a" "$SRC/Core/Core.a" "$SRC/Platform/Platform.a")
need=0; for a in "${ARCHIVES[@]}"; do [ -f "$a" ] || need=1; done
if [ "$need" = 1 ]; then
	[ "${VC_H2_SKIP_BUILD:-0}" = 1 ] && fail "product archives missing and VC_H2_SKIP_BUILD=1"
	log "archives missing — building: scripts/build-product.sh ${MAKE_ARGS[*]}"
	"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" >/tmp/am_build.log 2>&1 \
		|| fail "product build failed (see /tmp/am_build.log)"
fi

# HCTR2 needs ONLY AesCt — its POLYVAL is self-contained. (Adiantum additionally needs
# chacha256 + Poly1305; do not copy those in here, they are not dependencies of this mode.)
D="-DVC_ENABLE_HCTR2 -DVC_ENABLE_HCTR2_MODE -DVC_ENABLE_CTAES"
NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
INC="-I$SRC -I$SRC/Common -I$SRC/Crypto -I$SRC/PKCS11 -I$SRC/Crypto/Argon2/include"
BASE="-DTC_UNIX -DTC_LINUX -D_FILE_OFFSET_BITS=64 -DARGON2_NO_THREADS"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

log "compiling the Hctr2 crypto objects"
for f in Hctr2 AesCt; do
	$CC -O2 $D $NOASM $INC -c "$SRC/Crypto/$f.c" -o "$WORK/$f.o" 2>>"$WORK/cc.log" \
		|| fail "could not compile Crypto/$f.c (see $WORK/cc.log)"
done

# EncryptionModeHctr2.cpp is compiled HERE rather than taken from Volume.a: the archive only carries
# it when the product was built with HCTR2_MODE=1, and this test must not silently pass by linking a
# stale object (or fail confusingly when the flag was absent). Listing it before the archives also makes
# the link order unambiguous.
log "compiling the shim + test"
$CXX -O2 -std=c++17 $D $NOASM $BASE $INC -Wall -c "$SRC/Volume/EncryptionModeHctr2.cpp" -o "$WORK/mode.o" \
	2>>"$WORK/cc.log" || fail "could not compile EncryptionModeHctr2.cpp (see $WORK/cc.log)"
$CXX -O2 -std=c++17 $D $NOASM $BASE $INC -Wall -c "$HERE/../hctr2_mode_test.cpp" -o "$WORK/test.o" \
	2>>"$WORK/cc.log" || fail "could not compile hctr2_mode_test.cpp (see $WORK/cc.log)"

log "linking against the real product archives"
$CXX -o "$WORK/run" "$WORK/test.o" "$WORK/mode.o" "$WORK"/Hctr2.o "$WORK"/AesCt.o \
	-Wl,--start-group "${ARCHIVES[@]}" -Wl,--end-group \
	$(pkg-config fuse --libs 2>/dev/null) $(wx-config --libs base 2>/dev/null) -lpthread \
	2>>"$WORK/cc.log" || fail "link failed (see $WORK/cc.log)"

"$WORK/run" | sed 's/^/  /'
rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] || fail "the Hctr2 mode shim test failed (exit $rc)"
log "PASS — the shim is a true wide-block mode over the real EncryptionMode base"
