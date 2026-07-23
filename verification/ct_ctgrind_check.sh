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
vg_funcs () { # $1=binary $2=arg -> distinct functions memcheck flagged, comma-joined
	valgrind -q --error-exitcode=99 "$1" ${2:+$2} >/dev/null 2>/tmp/ctg_vg.txt || true
	grep -oE 'at 0x[0-9A-Fa-f]+: [A-Za-z_][A-Za-z0-9_]*' /tmp/ctg_vg.txt | sed 's/.*: //' | sort -u | paste -sd, - 2>/dev/null || true
}

# ct_ctgrind_test.c includes hctr2_poc.c (real gf_dot -> Crypto/Aes.h) and now also makes table AES a
# SUBJECT (A1) and links the real KeyslotConstTimeEqual (A2). So each build needs: the AES objects
# (Aescrypt/Aeskey/Aestab), and the keyslot objects (Keyslot + Sha2 + chacha256, built VC_ENABLE_KEYSLOTS
# with -ffunction-sections so --gc-sections drops the unused wrap/unwrap deps) — same recipes as the
# hctr2_dudect and keyslot_dudect suite steps.
WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
GC="-ffunction-sections -fdata-sections"

ok=1
for OPT in "-O2" "-O3" "-O2 -flto"; do
	for CC in gcc clang; do
		command -v "$CC" >/dev/null 2>&1 || continue
		if ! ( $CC $OPT $WNO $NOASM $INC -c "$SRCROOT/Crypto/Aescrypt.c" -o /tmp/ctg_aescrypt.o 2>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $INC -c "$SRCROOT/Crypto/Aeskey.c"   -o /tmp/ctg_aeskey.o   2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $INC -c "$SRCROOT/Crypto/Aestab.c"   -o /tmp/ctg_aestab.o   2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $GC -DVC_ENABLE_KEYSLOTS $INC -c "$SRCROOT/Common/Keyslot.c" -o /tmp/ctg_keyslot.o 2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $GC $INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/ctg_sha2.o   2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM $GC $INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ctg_chacha.o 2>>/tmp/ctg_build.log \
		    && $CC $OPT $WNO $NOASM -DCT_USE_VALGRIND -DVC_ENABLE_KEYSLOTS $INC "$HERE/ct_ctgrind_test.c" \
		         /tmp/ctg_aescrypt.o /tmp/ctg_aeskey.o /tmp/ctg_aestab.o \
		         /tmp/ctg_keyslot.o /tmp/ctg_sha2.o /tmp/ctg_chacha.o -lm -Wl,--gc-sections -o /tmp/ctg_bin 2>>/tmp/ctg_build.log ); then
			echo "  BUILD FAIL $CC $OPT"; grep -iv warning /tmp/ctg_build.log | head -3; ok=0; continue
		fi
		# masked/compare subjects: real must be clean (0), leaky must be flagged (>0)
		real=$(vg_errors /tmp/ctg_bin ""); leak=$(vg_errors /tmp/ctg_bin leaky)
		if [ "$real" -eq 0 ] && [ "$leak" -gt 0 ]; then verdict="PASS (masked+compare clean; leak caught)"; else verdict="FAIL"; ok=0; fi
		# A1 AES subject: a POSITIVE result is the expected FINDING, not a failure; record count+localization
		aes=$(vg_errors /tmp/ctg_bin aes)
		aesfn=$(vg_funcs /tmp/ctg_bin aes)
		if [ "$aes" -eq 0 ]; then aesnote="AES errs=0 (UNEXPECTED — suspect the harness)"; ok=0; else aesnote="AES errs=$aes in {$aesfn} (expected: table AES is cache-timing-leaky)"; fi
		printf "  %-10s %-6s  REAL=%-3s LEAK=%-3s  %s\n                       %s\n" "$OPT" "$CC" "$real" "$leak" "$verdict" "$aesnote"
	done
done

[ "$ok" = 1 ] && echo "CTGRIND PASS: masked primitives + keyslot compare clean at -O2/-O3/LTO (gcc+clang); leak caught; table AES flagged as expected (A1 finding)" \
             || { echo "CTGRIND FAIL"; exit 1; }
