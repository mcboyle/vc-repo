#!/bin/sh
# ct_ctgrind_check.sh — on-demand ctgrind (valgrind/memcheck) constant-time check for the project's
# masked secret-dependent primitives (research batch-3 R17 scaffold; see docs/CT-HARDENING-R17.md).
#
# Answers R17 Q1 empirically: does the arithmetic masking (mirroring Shamir.c) survive the compiler, or
# is a secret-dependent branch reintroduced at -O2 / -O3 / LTO? Poisons the SECRET operands
# (VALGRIND_MAKE_MEM_UNDEFINED) and runs the real primitives under memcheck at each opt level on gcc AND
# clang; a clean run == no secret-dependent control flow survived. Self-validating: the same check must
# FLAG a deliberately-branchy leaky copy.
#
# Kept OUT of build_and_verify.sh's --strict gate on purpose: it needs valgrind, which the privilege-free
# container is not guaranteed to have, and a hard dependency would turn "valgrind absent" into a strict
# failure. Run it where valgrind is available:  sh verification/ct_ctgrind_check.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRCROOT="$(cd "$HERE/../src" && pwd)"
INC="-I$SRCROOT -I$SRCROOT/Common -I$SRCROOT/Crypto"

if ! command -v valgrind >/dev/null 2>&1; then
	echo "SKIP: valgrind not installed (this check is valgrind-dependent by design; see the doc)"; exit 0
fi

vg_errors () { # $1=binary [$2=arg] -> memcheck uninitialised-value error count
	valgrind -q --error-exitcode=99 --track-origins=yes "$1" ${2:+$2} >/dev/null 2>/tmp/ctg_vg.txt || true
	grep -c "depends on uninitialised\|uninitialised value" /tmp/ctg_vg.txt || true
}

# ct_ctgrind_test.c includes hctr2_poc.c (for the REAL gf_dot), which pulls in Crypto/Aes.h and needs
# the AES objects at link time — same recipe as build_and_verify.sh's hctr2_dudect step. Build them
# per compiler + opt level (AES is unrelated to the masked primitives under test; it just has to link).
WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"

ok=1
for OPT in "-O2" "-O3" "-O2 -flto"; do
	for CC in gcc clang; do
		command -v "$CC" >/dev/null 2>&1 || continue
		if ! ( $CC $OPT $WNO $NOASM $INC -c "$SRCROOT/Crypto/Aescrypt.c" -o /tmp/ctg_aescrypt.o 2>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $INC -c "$SRCROOT/Crypto/Aeskey.c"   -o /tmp/ctg_aeskey.o   2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $INC -c "$SRCROOT/Crypto/Aestab.c"   -o /tmp/ctg_aestab.o   2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM -DCT_USE_VALGRIND $INC "$HERE/ct_ctgrind_test.c" \
		         /tmp/ctg_aescrypt.o /tmp/ctg_aeskey.o /tmp/ctg_aestab.o -lm -o /tmp/ctg_bin 2>>/tmp/ctg_build.log ); then
			echo "  BUILD FAIL $CC $OPT"; grep -iv warning /tmp/ctg_build.log | head -3; ok=0; continue
		fi
		real=$(vg_errors /tmp/ctg_bin ""); leak=$(vg_errors /tmp/ctg_bin leaky)
		if [ "$real" -eq 0 ] && [ "$leak" -gt 0 ]; then verdict="PASS (masking survived; leak caught)"; else verdict="FAIL"; ok=0; fi
		printf "  %-10s %-6s  REAL errs=%-3s  LEAKY errs=%-3s  %s\n" "$OPT" "$CC" "$real" "$leak" "$verdict"
	done
done

[ "$ok" = 1 ] && echo "CTGRIND PASS: no secret-dependent control flow in the masked primitives at -O2/-O3/LTO (gcc+clang); leak caught" \
             || { echo "CTGRIND FAIL"; exit 1; }
