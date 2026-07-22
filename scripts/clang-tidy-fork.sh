#!/usr/bin/env bash
# clang-tidy-fork.sh — static analysis over the fork's added Common modules (ROI-TOP-50 item 37).
# Uses the repo .clang-tidy config (bugprone-* / clang-analyzer-* / cert-*, WarningsAsErrors). Exits
# non-zero on any finding. CodeQL runs separately in CI (.github/workflows/codeql.yml).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CT="${CLANG_TIDY:-clang-tidy}"
command -v "$CT" >/dev/null 2>&1 || { echo "SKIP: $CT not installed"; exit 42; }

INC="-I$ROOT/src -I$ROOT/src/Common -I$ROOT/src/Crypto -I$ROOT/src/Crypto/Argon2/include"
DEFS="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_KEYSLOT_POLICY -DVC_ENABLE_KEYSCRUB -DVC_ENABLE_HKF -DVC_ENABLE_DURESS -DVC_ENABLE_SHAMIR_MAC -DVC_ENABLE_SHARECODE -DVC_ENABLE_SELFTEST -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"

# The modules this fork adds (stock VeraCrypt files are out of scope for the fork's static analysis).
MODULES="HardwareKeyFactor KeyScrub DuressToken Keyslot KeyslotStore AfSplit KeyslotAreaFile Shamir ShamirMac ShareCode SelfTest"

rc=0
for m in $MODULES; do
	f="$ROOT/src/Common/$m.c"
	[ -f "$f" ] || continue
	if "$CT" --quiet "$f" -- $INC $DEFS >"/tmp/ct_$m.out" 2>&1; then
		echo "  [clean] Common/$m.c"
	else
		echo "  [FINDINGS] Common/$m.c"; grep -E "warning:|error:" "/tmp/ct_$m.out" | head -8 | sed 's/^/      /'; rc=1
	fi
done
[ $rc -eq 0 ] && echo "clang-tidy: all $(echo $MODULES | wc -w) fork modules clean" || echo "clang-tidy: findings above"
exit $rc
