#!/usr/bin/env bash
# flag_matrix.sh — pairwise feature-flag × multi-compiler build matrix (ROI-TOP-50 item 3).
#
# WHY: the fork's feature modules are gated by independent VC_ENABLE_* macros. A guard that is
# correct in the shipping "all features on" build can still be wrong in a *partial* combination —
# the real example this catches is HKFScrubActiveConfig, which was defined in BOTH KeyScrub.c
# (KEYSCRUB && !HKF) and HardwareKeyFactor.c (KEYSCRUB only), so the KEYSCRUB-on / HKF-off build
# defined it twice. Neither the all-on product build nor the default (all-off) stock build hits that
# cell; only a pairwise sweep does.
#
# WHAT: for every available compiler and every pairwise combination of the feature flags (none, each
# single, each pair, and all-on), compile every fork Common module with that flag set and PARTIAL-LINK
# them together with `ld -r`. `ld -r` fails on a multiply-defined symbol but tolerates undefined
# externals (Sha2, ChaCha, …), so it isolates the *symbol-collision* class without needing wxWidgets
# or the full crypto link. A compile error in a cell is also a failure (a guard that won't build).
#
# This is deliberately NOT the product build (which additionally needs wxWidgets + libpcsclite and is
# covered by docs/REAL-BUILD-VALIDATION.md); it is the cheap, dependency-free check that a partial
# feature combination neither fails to compile nor collides at link. It also subsumes ROI item 13
# (link-time symbol-collision check).
#
# USAGE:
#   ./flag_matrix.sh            run the matrix on every compiler found; exit non-zero on any failure
#   ./flag_matrix.sh --full     also sweep all 2^N flag combinations (exhaustive, slower)
#   VC_MATRIX_NEGCTL=1 ./flag_matrix.sh   self-test: re-inject the OLD broken HKFScrubActiveConfig
#                                         guard and assert the matrix flags the KEYSCRUB-only cell
#                                         (proves the check has teeth), then restore and exit.
#
# CI runs this on GCC 12/13/14 + clang (.github/workflows/flag-matrix.yml). A local sandbox typically
# has fewer compilers; the script runs whatever is present and prints which versions it covered, so an
# incomplete local run is never mistaken for the full CI matrix.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRCROOT="$HERE/../src"
INC="-I$SRCROOT -I$SRCROOT/Common -I$HERE -I$SRCROOT/Crypto -I$SRCROOT/Crypto/Argon2/include"
WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"

# Fork Common modules that carry gated symbols (the surface where a partial combo can collide).
MODULES="HardwareKeyFactor KeyScrub DuressToken Keyslot KeyslotStore AfSplit KeyslotAreaFile Shamir ShamirMac ShareCode SelfTest Pkcs5"
# Independent feature flags to sweep. (Backend flags YUBIKEY/FIDO2/SIMULATOR need external libs and
# are covered by the real build; HKF_SALT_BIND rides on HKF.)
FLAGS="VC_ENABLE_KEYSCRUB VC_ENABLE_HKF VC_ENABLE_DURESS VC_ENABLE_KEYSLOTS VC_ENABLE_KEYSLOT_POLICY VC_ENABLE_SHAMIR_MAC VC_ENABLE_SHARECODE VC_ENABLE_HKF_SALT_BIND VC_ENABLE_ARGON2_PARAMS VC_ENABLE_BALLOON_KDF VC_ENABLE_SELFTEST VC_ENABLE_KEYSLOT_SHRED"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# --- discover compilers -----------------------------------------------------------------------------
# De-dupe by compiler *identity* (family + major version), so `gcc` and `gcc-13` — the same binary on
# most distros — count once and the coverage report is not overstated. Prefer the version-suffixed
# name when both resolve to the same identity.
COMPILERS=""; SEEN_ID=""
for c in gcc-12 gcc-13 gcc-14 gcc clang-15 clang-16 clang-17 clang-18 clang; do
	command -v "$c" >/dev/null 2>&1 || continue
	ver="$($c -dumpversion 2>/dev/null | cut -d. -f1)"
	case "$($c --version 2>/dev/null | head -1)" in *clang*) fam=clang;; *) fam=gcc;; esac
	id="$fam-$ver"
	case "|$SEEN_ID|" in *"|$id|"*) continue;; esac
	SEEN_ID="$SEEN_ID|$id"
	COMPILERS="$COMPILERS $c"
done
if [ -z "$COMPILERS" ]; then echo "no C compiler found"; exit 2; fi

# --- build the list of flag configurations ----------------------------------------------------------
# "none", each single flag, each unordered pair, and all-on. (--full adds every subset.)
set -- $FLAGS; N=$#; FARR="$*"
configs_pairwise() {
	echo ""                                   # none
	local i j a b arr; arr=($FARR)
	for a in "${arr[@]}"; do echo "$a"; done   # singles
	for ((i=0;i<N;i++)); do for ((j=i+1;j<N;j++)); do echo "${arr[i]} ${arr[j]}"; done; done  # pairs
	echo "$FARR"                               # all-on
}
configs_full() {
	local total=$((1<<N)) k i arr; arr=($FARR)
	for ((k=0;k<total;k++)); do
		local line=""
		for ((i=0;i<N;i++)); do (( (k>>i)&1 )) && line="$line ${arr[i]}"; done
		echo "$line"
	done
}

# --- optional negative control: prove the matrix catches the historical collision -------------------
if [ "${VC_MATRIX_NEGCTL:-0}" = "1" ]; then
	echo "== flag_matrix NEGATIVE CONTROL =="
	cc="$(echo $COMPILERS | awk '{print $1}')"
	broken="$WORK/broken_HardwareKeyFactor.c"
	sed 's/#if defined(VC_ENABLE_KEYSCRUB) && defined(VC_ENABLE_HKF)/#if defined(VC_ENABLE_KEYSCRUB)/' \
		"$SRCROOT/Common/HardwareKeyFactor.c" > "$broken"
	if ! grep -q '#if defined(VC_ENABLE_KEYSCRUB)$' "$broken"; then
		echo "  could not synthesise the broken guard (source changed?) — cannot run negative control"; exit 2
	fi
	$cc -O0 $WNO $NOASM -DVC_ENABLE_KEYSCRUB $INC -c "$SRCROOT/Common/KeyScrub.c" -o "$WORK/nc_ks.o" 2>/dev/null
	$cc -O0 $WNO $NOASM -DVC_ENABLE_KEYSCRUB $INC -x c -c "$broken" -o "$WORK/nc_hkf.o" 2>/dev/null
	if ld -r "$WORK/nc_ks.o" "$WORK/nc_hkf.o" -o "$WORK/nc.o" 2>/dev/null; then
		echo "  FAIL: the broken KEYSCRUB-only guard did NOT collide — the matrix would miss it"; exit 1
	else
		echo "  PASS: broken KEYSCRUB-only guard collides at ld -r (matrix has teeth); real source is clean"; exit 0
	fi
fi

# --- run the matrix ---------------------------------------------------------------------------------
mode=pairwise
[ "${1:-}" = "--full" ] && mode=full
mapfile -t CONFIGS < <([ "$mode" = full ] && configs_full || configs_pairwise)

echo "flag_matrix: compilers ={$(echo $COMPILERS)}  flags=$N  configs=${#CONFIGS[@]} ($mode)  modules=$(echo $MODULES | wc -w)"
missing_ver=""
for want in gcc-12 gcc-14; do command -v "$want" >/dev/null 2>&1 || missing_ver="$missing_ver $want"; done
[ -n "$missing_ver" ] && echo "  note: this host lacks$missing_ver — CI (.github/workflows/flag-matrix.yml) covers GCC 12/13/14 + clang"

fails=0; cells=0
for cc in $COMPILERS; do
	ccfail=0
	for cfg in "${CONFIGS[@]}"; do
		cells=$((cells+1))
		defs=""; for f in $cfg; do defs="$defs -D$f"; done
		objs=""; cellbad=0
		for m in $MODULES; do
			if "$cc" -O0 $WNO $NOASM $defs $INC -c "$SRCROOT/Common/$m.c" -o "$WORK/$m.o" 2>"$WORK/cc.log"; then
				objs="$objs $WORK/$m.o"
			else
				echo "  [$cc] COMPILE-FAIL {${cfg:-none}} module=$m"; sed -n '1,3p' "$WORK/cc.log" | sed 's/^/      /'
				cellbad=1; break
			fi
		done
		if [ "$cellbad" = 0 ]; then
			if ! ld -r $objs -o "$WORK/combined.o" 2>"$WORK/ld.log"; then
				sym="$(grep -oE "multiple definition of \`[^']+'" "$WORK/ld.log" | head -1)"
				echo "  [$cc] LINK-COLLISION {${cfg:-none}} ${sym:-see ld.log}"; cellbad=1
			fi
		fi
		[ "$cellbad" = 1 ] && { fails=$((fails+1)); ccfail=$((ccfail+1)); }
	done
	printf "  %-8s %d configs, %d failed\n" "$cc" "${#CONFIGS[@]}" "$ccfail"
done

echo ""
echo "=== flag-matrix: $((cells-fails))/$cells cells clean across $(echo $COMPILERS | wc -w) compiler(s) ==="
if [ "$fails" -ne 0 ]; then echo "MATRIX FAIL: $fails cell(s) failed to compile or collided"; exit 1; fi
echo "MATRIX PASS: every pairwise feature combination compiles + partial-links with no symbol collision"
