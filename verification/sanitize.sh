#!/usr/bin/env bash
# sanitize.sh — rebuild the behavioural harnesses under ASan+UBSan and run them (ROI-TOP-50 item 33).
#
# Items 31/32 sanitize the two attacker-facing PARSERS. This extends ASan+UBSan across the rest of the
# suite's behavioural harnesses — the keyslot lifecycle, per-slot policy, KeyScrub, duress, and Shamir
# — so a memory-safety or UB bug anywhere in the shipping modules those harnesses drive is caught, not
# just in the fuzz targets. The sanitizers are the oracle; every harness must still exit 0 with no
# AddressSanitizer / UBSan diagnostic.
#
# Needs a sanitizer-capable toolchain (gcc ships libasan; a clang without compiler-rt is skipped). A
# built-in negative control compiles a tiny known-buggy program under the SAME flags and confirms the
# sanitizer catches it — so a mis-configured (silently inactive) sanitizer fails the sweep too.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/../src"
WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -g"
DEFS="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_KEYSLOT_POLICY -DVC_ENABLE_KEYSCRUB -DVC_ENABLE_HKF -DVC_ENABLE_DURESS -DVC_ENABLE_SHAMIR_MAC -DVC_ENABLE_SHARECODE -DVC_ENABLE_SELFTEST"
INC="-I$SRC -I$SRC/Common -I$HERE -I$SRC/Crypto"
GC="-ffunction-sections -fdata-sections"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# pick a sanitizer-capable compiler
CC=""
for c in gcc-14 gcc-13 gcc cc clang; do
	command -v "$c" >/dev/null 2>&1 || continue
	printf 'int main(){return 0;}\n' > "$W/probe.c"
	if "$c" -fsanitize=address,undefined "$W/probe.c" -o "$W/probe" 2>/dev/null; then CC="$c"; break; fi
done
if [ -z "$CC" ]; then echo "SKIP: no sanitizer-capable compiler (gcc libasan)"; exit 42; fi

# --- negative control: a known heap-overflow must be caught under these exact flags ---
cat > "$W/neg.c" <<'EOF'
#include <stdlib.h>
#include <string.h>
int main(void){ char *p=(char*)malloc(8); memset(p,0,16); return p[0]; }
EOF
"$CC" -O1 $SAN "$W/neg.c" -o "$W/neg" 2>/dev/null
if "$W/neg" >/dev/null 2>&1; then echo "NEG-CONTROL FAILED: sanitizer did not catch a heap overflow (inactive?)"; exit 1; fi
echo "  neg-control: heap overflow caught under $CC ASan/UBSan (sanitizer is active)"

# --- shared module objects, built once under the sanitizer with the full feature set ---
MODS="Keyslot KeyslotStore AfSplit KeyslotAreaFile KeyScrub HardwareKeyFactor DuressToken Shamir ShamirMac ShareCode SelfTest"
CRYPTO="Sha2 Sha3 t1ha2 chacha256 chachaRng"
OBJS=""
for m in $MODS; do
	"$CC" -O1 $WNO $NOASM $SAN $GC $DEFS $INC -c "$SRC/Common/$m.c" -o "$W/$m.o" || { echo "FAIL compiling Common/$m.c"; exit 1; }
	OBJS="$OBJS $W/$m.o"
done
for m in $CRYPTO; do
	"$CC" -O1 $WNO $NOASM $SAN $GC $INC -c "$SRC/Crypto/$m.c" -o "$W/c_$m.o" || { echo "FAIL compiling Crypto/$m.c"; exit 1; }
	OBJS="$OBJS $W/c_$m.o"
done

# --- run each behavioural harness under the sanitizer ---
HARNESSES="keyslot_store_test keyslot_policy_test keyscrub_selftest duress_selftest shamir_test"
clean=0
for h in $HARNESSES; do
	# shamir_test.c #includes Shamir.c directly, so it must NOT also link the shared Shamir.o.
	hobjs="$OBJS"; [ "$h" = shamir_test ] && hobjs=""
	if ! "$CC" -O1 $WNO $NOASM $SAN $DEFS $INC "$HERE/$h.c" $hobjs -lpthread -Wl,--gc-sections -o "$W/$h" 2>"$W/$h.clog"; then
		echo "  FAIL: $h did not build under sanitizers"; sed -n '1,4p' "$W/$h.clog" | sed 's/^/      /'; exit 1
	fi
	if "$W/$h" > "$W/$h.out" 2>&1; then
		echo "  [sanitized] $h: clean"
		clean=$((clean+1))
	else
		echo "  FAIL: $h faulted under ASan/UBSan"; grep -iE "AddressSanitizer|runtime error|SUMMARY" "$W/$h.out" | head -3 | sed 's/^/      /'; exit 1
	fi
done
echo "=== sanitizer sweep: $clean/$(echo $HARNESSES | wc -w) behavioural harnesses clean under $CC ASan+UBSan ==="
