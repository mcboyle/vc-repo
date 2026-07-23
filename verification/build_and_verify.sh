#!/usr/bin/env bash
# Reproduce the self-contained HardwareKeyFactor verification (crypto/mixing + CLI parsing).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"; SRCROOT="$HERE/../src"
INC="-I$SRCROOT -I$SRCROOT/Common -I$HERE"

# --- coverage accounting + strict mode (ROI item 1) -------------------------------------------------
# A "step" is a top-level `echo "[N] ..."` header; a step that cannot build its harness prints a SKIP
# via skip_step (compiler/lib absent). The suite already exit 1s on any real MISMATCH/FAILED, so if we
# reach the end, every non-skipped step verified: PASS = TOTAL - SKIP. --strict (or VC_STRICT=1) turns
# any SKIP into a non-zero exit, so a partially-covered run can never masquerade as fully green.
STRICT=0
for a in "$@"; do case "$a" in --strict) STRICT=1;; --help|-h) echo "usage: $(basename "$0") [--strict]"; exit 0;; esac; done
[ "${VC_STRICT:-0}" = "1" ] && STRICT=1
STEP_TOTAL="$(grep -cE '^echo "\[[0-9]+\]' "$HERE/$(basename "$0")" 2>/dev/null || echo 0)"
STEP_SKIP=0
skip_step() { printf '    SKIP:%s\n' "$1"; STEP_SKIP=$((STEP_SKIP + 1)); }
verify_summary() {
	rc=$?
	echo ""
	# Honesty guard: a non-zero exit means a step hit a MISMATCH/FAILED or the suite aborted (set -e)
	# BEFORE reaching the end. In that case we must NOT print a reassuring "N/N verified" line — the
	# counts are meaningless because the run did not complete. Report the failure plainly instead.
	if [ "$rc" -ne 0 ]; then
		echo "=== FAILED (exit $rc): suite did not complete all $STEP_TOTAL steps; coverage is unreliable ==="
		exit "$rc"
	fi
	echo "=== coverage: $((STEP_TOTAL - STEP_SKIP))/$STEP_TOTAL steps verified, $STEP_SKIP skipped ==="
	if [ "$STRICT" = 1 ] && [ "$STEP_SKIP" -gt 0 ]; then
		echo "STRICT: $STEP_SKIP of $STEP_TOTAL step(s) skipped (harness/toolchain incomplete) -> FAIL"
		exit 3
	fi
}
trap verify_summary EXIT
# Negative control for strict mode itself: VC_SELFTEST_FORCE_SKIP=1 injects one artificial SKIP and
# exits early (before the ~5-min real steps), so the accounting can be exercised cheaply:
#   VC_SELFTEST_FORCE_SKIP=1 ./build_and_verify.sh           -> exit 0, coverage shows 1 skipped
#   VC_SELFTEST_FORCE_SKIP=1 ./build_and_verify.sh --strict  -> exit 3 (a skip fails the suite)
if [ "${VC_SELFTEST_FORCE_SKIP:-0}" = "1" ]; then
	echo "[strict-mode self-test] injecting one artificial SKIP to exercise --strict / coverage"
	skip_step " artificial (VC_SELFTEST_FORCE_SKIP negative control — not a real coverage run)"
	exit 0
fi
# ---------------------------------------------------------------------------------------------------
echo "[1] compile module (simulator backend)"
gcc -O2 -DVC_ENABLE_HKF_SIMULATOR $INC -c "$SRCROOT/Common/HardwareKeyFactor.c" -o /tmp/hkf.o
echo "[2] crypto + mixing selftest vs independent python reference"
gcc -O2 -DVC_ENABLE_HKF_SIMULATOR $INC "$HERE/hkf_selftest.c" /tmp/hkf.o -o /tmp/hkf_selftest
/tmp/hkf_selftest > /tmp/hkf_c.txt; cat /tmp/hkf_c.txt
python3 "$HERE/reference_check.py" > /tmp/hkf_py.txt
if diff -q /tmp/hkf_c.txt /tmp/hkf_py.txt >/dev/null; then echo "    MATCH: module == reference"; else echo "    MISMATCH"; diff /tmp/hkf_c.txt /tmp/hkf_py.txt; exit 1; fi
echo "[3] CLI option parsing test (parses strings -> HKFConfig -> real crypto)"
g++ -O2 -std=c++14 -DVC_ENABLE_HKF $INC "$HERE/hkf_cli_test.cpp" /tmp/hkf.o -o /tmp/hkf_cli && /tmp/hkf_cli
echo ""; echo "OK: standalone verification passed."
echo "Note: hkf_cpp.cpp (C++ seam vs real Pkcs5HmacSha3_512) needs the compiled VeraCrypt C++ objects"
echo "      and is included for reference; its result is reported in the README."

echo ""
echo "[5] Shamir threshold: GF(2^8) KATs + split/combine + threshold property"
gcc -O2 -I"$SRCROOT" -I"$SRCROOT/Common" "$HERE/shamir_test.c" -o /tmp/shamir_test
/tmp/shamir_test > /tmp/shamir_c.txt || { echo "shamir_test FAILED"; cat /tmp/shamir_c.txt; exit 1; }
sed -n '1,14p' /tmp/shamir_c.txt
python3 - /tmp/shamir_c.txt <<'PYEOF'
import sys,re
exp=[0]*512; log=[0]*256; x=1
for i in range(255):
    exp[i]=x; log[x]=i; hi=x&0x80; x=(x<<1)&0xff
    if hi: x^=0x1b
    x^=exp[i]
for i in range(255,512): exp[i]=exp[i-255]
def mul(a,b): return 0 if (a==0 or b==0) else exp[log[a]+log[b]]
def poly(c,xx):
    r=c[-1]
    for k in reversed(c[:-1]): r=mul(r,xx)^k
    return r
secret=bytes(0x10+i for i in range(32)); T,N,L=3,5,32
rnd=bytes(((i*7+1)&0xff) for i in range((T-1)*L))
sh={s:bytes(poly([secret[b]]+[rnd[(k-1)*L+b] for k in range(1,T)],s) for b in range(L)) for s in range(1,N+1)}
c={}
for ln in open(sys.argv[1]):
    m=re.match(r'^(\d+):([0-9a-fA-F]+)\s*$',ln)
    if m: c[int(m.group(1))]=bytes.fromhex(m.group(2))
print("    python shares == C shares:", "YES" if all(sh[k]==c.get(k) for k in sh) else "MISMATCH")
PYEOF
echo "    (shamir_chain.c full-derive check requires compiled VeraCrypt objects; see SPLIT-KEY-SPEC.md)"

echo ""
echo "[6] KeyScrub: secure-wipe + registry + RAM-encryption transform vs independent python reference"
# The stock Crypto sources use the 'static VC_INLINE' idiom and an SSSE3 asm path. Pick a compiler
# that accepts the idiom (clang warns where gcc 13+ errors) and build the portable C crypto path
# (CRYPTOPP_DISABLE_*); the pure-C keystream is byte-identical to the asm path. t1ha2/chacha256 here
# are the REAL in-tree VeraCrypt objects (layer 2); keyscrub_reference.py is the independent
# reimplementation (layer 1).
KS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KS_CC="$c"; break; fi; done
KS_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
KS_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
# KEYSCRUB and HKF are both defined so this exercises the REAL HKFScrubActiveConfig (test [F] asserts
# the reconstructed secret is wiped): with KEYSCRUB alone the KeyScrub.c empty stub would run and [F]
# would (correctly) report NO. The two definitions are guard-complementary (KeyScrub.c: KEYSCRUB &&
# !HKF stub; HardwareKeyFactor.c: KEYSCRUB && HKF real), so building both objects never collides.
KS_DEF="-DVC_ENABLE_KEYSCRUB -DVC_ENABLE_HKF"
if "$KS_CC" -O2 $KS_WNO $KS_NOASM $KS_DEF $INC -c "$SRCROOT/Common/KeyScrub.c" -o /tmp/ks_keyscrub.o 2>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $KS_DEF $INC -c "$SRCROOT/Common/HardwareKeyFactor.c" -o /tmp/ks_hkf.o 2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $INC -c "$SRCROOT/Crypto/t1ha2.c"     -o /tmp/ks_t1ha2.o     2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ks_chacha256.o 2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $INC -c "$SRCROOT/Crypto/chachaRng.c" -o /tmp/ks_chachaRng.o 2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_DEF $INC "$HERE/keyscrub_selftest.c" \
        /tmp/ks_keyscrub.o /tmp/ks_hkf.o /tmp/ks_t1ha2.o /tmp/ks_chacha256.o /tmp/ks_chachaRng.o -lpthread -o /tmp/keyscrub_selftest 2>>/tmp/ks_cc.log; then
	/tmp/keyscrub_selftest > /tmp/ks_c.txt; cat /tmp/ks_c.txt
	python3 "$HERE/keyscrub_reference.py" > /tmp/ks_py.txt
	grep '^REF' /tmp/ks_c.txt > /tmp/ks_c_ref.txt
	if diff -q /tmp/ks_c_ref.txt /tmp/ks_py.txt >/dev/null; then
		echo "    MATCH: KeyScrub transform (real t1ha2/chacha objects) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/ks_c_ref.txt /tmp/ks_py.txt; exit 1
	fi
	# all boolean self-checks must report YES (incl. the [L] present-before/absent-after liveness pairs)
	if grep -Eq ': NO$' /tmp/ks_c.txt; then echo "    KEYSCRUB SELFTEST FAILED"; exit 1; fi
	# Negative control (ROI item 2): rebuild the SAME selftest with the wipe disabled and confirm the
	# liveness checks have teeth — "present before" must stay YES, "absent after" must flip to NO. If
	# the wipe were a silent no-op in the real build, this is the run that would have caught it.
	if "$KS_CC" -O2 $KS_WNO $KS_DEF -DVC_NEGCTL_NO_WIPE $INC "$HERE/keyscrub_selftest.c" \
	     /tmp/ks_keyscrub.o /tmp/ks_hkf.o /tmp/ks_t1ha2.o /tmp/ks_chacha256.o /tmp/ks_chachaRng.o -lpthread -o /tmp/keyscrub_negctl 2>>/tmp/ks_cc.log; then
		/tmp/keyscrub_negctl > /tmp/ks_neg.txt
		nc_ok=1
		grep -q '^\[L1\] secret present before wipe: YES$'   /tmp/ks_neg.txt || nc_ok=0
		grep -q '^\[L1\] secret absent after wipe: NO$'      /tmp/ks_neg.txt || nc_ok=0
		grep -q '^\[L2\] HKF secret present before scrub: YES$' /tmp/ks_neg.txt || nc_ok=0
		grep -q '^\[L2\] HKF secret absent after scrub: NO$'    /tmp/ks_neg.txt || nc_ok=0
		if [ "$nc_ok" = 1 ]; then
			echo "    NEG-CONTROL: with the wipe disabled the liveness checks correctly report the secret NOT scrubbed (checks have teeth)"
		else
			echo "    NEG-CONTROL FAILED: liveness assertions did not flip when the wipe was disabled — they are vacuous"; cat /tmp/ks_neg.txt; exit 1
		fi
	else
		echo "    NEG-CONTROL build failed (see /tmp/ks_cc.log)"; exit 1
	fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ks_cc.log)"
fi

echo ""
echo "[7] Duress token: HMAC-SHA256(salt,passphrase) vs independent python reference + constant-time match"
# DuressToken links the REAL in-tree Sha2.c (SHA-256); duress_reference.py is an independent
# HMAC-SHA256 (ipad/opad over hashlib). --gc-sections drops the unused KDFs sharing Sha2's TU.
DT_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then DT_CC="$c"; break; fi; done
DT_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
DT_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
DT_GC="-ffunction-sections -fdata-sections"
DT_INC="$INC -I$SRCROOT/Crypto"
if "$DT_CC" -O2 $DT_WNO $DT_NOASM $DT_GC -DVC_ENABLE_DURESS $DT_INC -c "$SRCROOT/Common/DuressToken.c" -o /tmp/dt.o 2>/tmp/dt_cc.log \
   && "$DT_CC" -O2 $DT_WNO $DT_NOASM $DT_GC $DT_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/dt_sha2.o 2>>/tmp/dt_cc.log \
   && "$DT_CC" -O2 $DT_WNO $DT_NOASM -DVC_ENABLE_DURESS $DT_INC "$HERE/duress_selftest.c" \
        /tmp/dt.o /tmp/dt_sha2.o -Wl,--gc-sections -o /tmp/duress_selftest 2>>/tmp/dt_cc.log; then
	/tmp/duress_selftest > /tmp/d_c.txt; cat /tmp/d_c.txt
	python3 "$HERE/duress_reference.py" > /tmp/d_py.txt
	grep '^REF' /tmp/d_c.txt > /tmp/d_c_ref.txt
	if diff -q /tmp/d_c_ref.txt /tmp/d_py.txt >/dev/null; then
		echo "    MATCH: DuressToken (real Sha2 object) == independent python HMAC-SHA256"
	else
		echo "    MISMATCH"; diff /tmp/d_c_ref.txt /tmp/d_py.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/d_c.txt; then echo "    DURESS SELFTEST FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/dt_cc.log)"
fi

echo ""
echo "[8] Keyslots PoC: per-slot master-key wrap/unwrap (PBKDF2->ChaCha20+HMAC) vs independent python"
# Proof-of-concept anchoring docs/KEYSLOTS-SPEC.md. Links the REAL in-tree Sha2.c + chacha256.c;
# keyslot_reference.py is independent (hashlib PBKDF2/HMAC + reimplemented ChaCha20).
KP_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KP_CC="$c"; break; fi; done
KP_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
KP_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KP_GC="-ffunction-sections -fdata-sections"
KP_INC="$INC -I$SRCROOT/Crypto"
if "$KP_CC" -O2 $KP_WNO $KP_NOASM $KP_GC $KP_INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/kp_sha2.o 2>/tmp/kp_cc.log \
   && "$KP_CC" -O2 $KP_WNO $KP_NOASM $KP_GC $KP_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/kp_chacha.o 2>>/tmp/kp_cc.log \
   && "$KP_CC" -O2 $KP_WNO $KP_NOASM $KP_INC "$HERE/keyslot_poc.c" \
        /tmp/kp_sha2.o /tmp/kp_chacha.o -Wl,--gc-sections -o /tmp/keyslot_poc 2>>/tmp/kp_cc.log; then
	/tmp/keyslot_poc > /tmp/kp_c.txt; cat /tmp/kp_c.txt
	python3 "$HERE/keyslot_reference.py" > /tmp/kp_py.txt
	grep '^REF' /tmp/kp_c.txt > /tmp/kp_c_ref.txt
	if diff -q /tmp/kp_c_ref.txt /tmp/kp_py.txt >/dev/null; then
		echo "    MATCH: keyslot wrap/unwrap (real Sha2/chacha objects) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/kp_c_ref.txt /tmp/kp_py.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/kp_c.txt; then echo "    KEYSLOT POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/kp_cc.log)"
fi

echo ""
echo "[9] Keyslots lifecycle: real Keyslot.c + KeyslotStore.c over in-memory areas (add/open/rotate/revoke)"
# Behavioural end-to-end test of the shipping modules (the wrapping crypto itself is proven in [8]).
KL_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KL_CC="$c"; break; fi; done
KL_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
KL_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KL_GC="-ffunction-sections -fdata-sections"
KL_INC="$INC -I$SRCROOT/Crypto"
# KeyslotStore.c calls AfSplit/AfMerge (Common/AfSplit.c, gated on VC_ENABLE_KEYSLOTS) for the
# anti-forensic record format, so AfSplit.o must be on the link line — without it the harness
# link fails with "undefined reference to AfSplit" and (pre strict-mode) silently SKIPped.
if "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC -DVC_ENABLE_KEYSLOTS $KL_INC -c "$SRCROOT/Common/Keyslot.c"      -o /tmp/kl_keyslot.o 2>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC -DVC_ENABLE_KEYSLOTS $KL_INC -c "$SRCROOT/Common/KeyslotStore.c" -o /tmp/kl_store.o 2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC -DVC_ENABLE_KEYSLOTS $KL_INC -c "$SRCROOT/Common/AfSplit.c"      -o /tmp/kl_af.o    2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC $KL_INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/kl_sha2.o   2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC $KL_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/kl_chacha.o 2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM -DVC_ENABLE_KEYSLOTS $KL_INC "$HERE/keyslot_store_test.c" \
        /tmp/kl_keyslot.o /tmp/kl_store.o /tmp/kl_af.o /tmp/kl_sha2.o /tmp/kl_chacha.o -Wl,--gc-sections -o /tmp/keyslot_store_test 2>>/tmp/kl_cc.log; then
	if /tmp/keyslot_store_test > /tmp/kl_out.txt; then cat /tmp/kl_out.txt
	else cat /tmp/kl_out.txt; echo "    KEYSLOT LIFECYCLE FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/kl_cc.log)"
fi

echo ""
echo "[10] Network-bound share: McCallum-Relyea exchange vs independent python (server never sees the key)"
# Proof-of-concept for the Tang/Clevis-style share source (docs/NETWORK-SHARE-SPEC.md). Links the REAL
# in-tree Sha2.c for the share hash; netshare_reference.py is the independent reference (python bigint).
NS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then NS_CC="$c"; break; fi; done
NS_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
NS_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
NS_GC="-ffunction-sections -fdata-sections"
NS_INC="$INC -I$SRCROOT/Crypto"
if "$NS_CC" -O2 $NS_WNO $NS_NOASM $NS_GC $NS_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/ns_sha2.o 2>/tmp/ns_cc.log \
   && "$NS_CC" -O2 $NS_WNO $NS_NOASM $NS_INC "$HERE/netshare_poc.c" /tmp/ns_sha2.o -Wl,--gc-sections -o /tmp/netshare_poc 2>>/tmp/ns_cc.log; then
	/tmp/netshare_poc > /tmp/ns_c.txt; cat /tmp/ns_c.txt
	python3 "$HERE/netshare_reference.py" > /tmp/ns_py.txt
	grep '^REF' /tmp/ns_c.txt > /tmp/ns_c_ref.txt
	if diff -q /tmp/ns_c_ref.txt /tmp/ns_py.txt >/dev/null; then
		echo "    MATCH: McCallum-Relyea exchange (real Sha2 object) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/ns_c_ref.txt /tmp/ns_py.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/ns_c.txt; then echo "    NETSHARE POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ns_cc.log)"
fi

echo ""
echo "[11] Argon2id explicit params: RFC 9106 KAT + parallelism plumbing + resolver vs python"
# The Argon2 algorithm is anchored to the published RFC 9106 vector inside the harness (real in-tree
# argon2). This step proves the override plumbs memory/iterations/parallelism and that the resolver
# formula matches an independent Python reimplementation. Links the REAL Pkcs5.c + Argon2 sources
# (reference fill_segment path via stub CPU flags; --gc-sections drops the other PRFs in Pkcs5's TU).
AP_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then AP_CC="$c"; break; fi; done
AP_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
AP_GC="-ffunction-sections -fdata-sections"
AP_INC="$INC -I$SRCROOT/Crypto -I$SRCROOT/Crypto/Argon2/include -I$SRCROOT/Crypto/Argon2/src"
AP_ARG="$SRCROOT/Crypto/Argon2/src"
printf 'volatile int g_hasSSE2=1,g_hasAVX2=0,g_hasSSE42=0,g_hasAVX=0,g_hasSSSE3=0,g_hasAESNI=0,g_hasSHA256=0,g_isIntel=0,g_isAMD=0,g_hasSSE41=0,g_hasRDRAND=0,g_hasRDSEED=0;\n' > /tmp/ap_stub.c
if "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS $AP_INC -c "$AP_ARG/argon2.c" -o /tmp/ap_argon2.o 2>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS $AP_INC -c "$AP_ARG/core.c"   -o /tmp/ap_core.o   2>>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS $AP_INC -c "$AP_ARG/ref.c"    -o /tmp/ap_ref.o    2>>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS $AP_INC -c "$AP_ARG/blake2/blake2b.c" -o /tmp/ap_b2.o 2>>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS -msse2 $AP_INC -c "$AP_ARG/opt_sse2.c" -o /tmp/ap_sse2.o 2>>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS -mavx2 -msse2 $AP_INC -c "$AP_ARG/opt_avx2.c" -o /tmp/ap_avx2.o 2>>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO $AP_GC -DARGON2_NO_THREADS -DVC_ENABLE_ARGON2_PARAMS $AP_INC -c "$SRCROOT/Common/Pkcs5.c" -o /tmp/ap_pkcs5.o 2>>/tmp/ap_cc.log \
   && "$AP_CC" -O2 $AP_WNO -DARGON2_NO_THREADS -DVC_ENABLE_ARGON2_PARAMS $AP_INC "$HERE/argon2_params_test.c" /tmp/ap_stub.c \
        /tmp/ap_pkcs5.o /tmp/ap_argon2.o /tmp/ap_core.o /tmp/ap_ref.o /tmp/ap_b2.o /tmp/ap_sse2.o /tmp/ap_avx2.o \
        -Wl,--gc-sections -o /tmp/argon2_params_test 2>>/tmp/ap_cc.log; then
	/tmp/argon2_params_test > /tmp/ap_c.txt; cat /tmp/ap_c.txt
	python3 "$HERE/argon2_params_reference.py" > /tmp/ap_py.txt
	grep '^REF' /tmp/ap_c.txt > /tmp/ap_c_ref.txt
	if diff -q /tmp/ap_c_ref.txt /tmp/ap_py.txt >/dev/null; then
		echo "    MATCH: Argon2 param resolver == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/ap_c_ref.txt /tmp/ap_py.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/ap_c.txt; then echo "    ARGON2 PARAMS TEST FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Argon2/Pkcs5 sources (see /tmp/ap_cc.log)"
fi

echo ""
echo "[12] RAW_SECRET salt-binding: real HKFComputeResponse == HMAC-SHA256(secret,salt) vs python"
# Drives the REAL Common/HardwareKeyFactor.c with a RAW_SECRET config whose rawSecretBindSalt is set;
# the response must be HMAC-SHA256(secret, salt) over the real in-tree Sha2.c. Independent ref: python hmac.
SB_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SB_CC="$c"; break; fi; done
SB_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
SB_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
SB_GC="-ffunction-sections -fdata-sections"
SB_INC="$INC -I$SRCROOT/Crypto"
if "$SB_CC" -O2 $SB_WNO $SB_NOASM $SB_GC -DVC_ENABLE_HKF -DVC_ENABLE_HKF_SALT_BIND $SB_INC -c "$SRCROOT/Common/HardwareKeyFactor.c" -o /tmp/sb_hkf.o 2>/tmp/sb_cc.log \
   && "$SB_CC" -O2 $SB_WNO $SB_NOASM $SB_GC $SB_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/sb_sha2.o 2>>/tmp/sb_cc.log \
   && "$SB_CC" -O2 $SB_WNO $SB_NOASM -DVC_ENABLE_HKF -DVC_ENABLE_HKF_SALT_BIND $SB_INC "$HERE/saltbind_test.c" /tmp/sb_hkf.o /tmp/sb_sha2.o -Wl,--gc-sections -o /tmp/saltbind_test 2>>/tmp/sb_cc.log; then
	/tmp/saltbind_test > /tmp/sb_c.txt; cat /tmp/sb_c.txt
	python3 "$HERE/saltbind_reference.py" > /tmp/sb_py.txt
	grep '^REF' /tmp/sb_c.txt > /tmp/sb_c_ref.txt
	if diff -q /tmp/sb_c_ref.txt /tmp/sb_py.txt >/dev/null; then
		echo "    MATCH: RAW_SECRET salt-binding (real HKF + Sha2) == independent python HMAC-SHA256"
	else
		echo "    MISMATCH"; diff /tmp/sb_c_ref.txt /tmp/sb_py.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/sb_c.txt; then echo "    SALTBIND TEST FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock sources (see /tmp/sb_cc.log)"
fi

echo ""
echo "[13] Write-only ORAM: access-pattern hiding (multi-snapshot deniability) vs independent python"
# HIVE-style write-only ORAM: every write touches K uniform physical blocks (fresh ChaCha20 ciphertext)
# independent of the logical target, so a public-only and a public+hidden workload produce an IDENTICAL
# observable access trace. Links the REAL in-tree chacha256.c + Sha2.c; oram_reference.py is independent.
OR_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then OR_CC="$c"; break; fi; done
OR_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
OR_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
OR_GC="-ffunction-sections -fdata-sections"
OR_INC="$INC -I$SRCROOT/Crypto"
if "$OR_CC" -O2 $OR_WNO $OR_NOASM $OR_GC $OR_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/or_cc.o 2>/tmp/or_log \
   && "$OR_CC" -O2 $OR_WNO $OR_NOASM $OR_GC $OR_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/or_sha2.o 2>>/tmp/or_log \
   && "$OR_CC" -O2 $OR_WNO $OR_NOASM $OR_INC "$HERE/oram_poc.c" /tmp/or_cc.o /tmp/or_sha2.o -Wl,--gc-sections -o /tmp/oram_poc 2>>/tmp/or_log; then
	/tmp/oram_poc > /tmp/or_c.txt; cat /tmp/or_c.txt
	python3 "$HERE/oram_reference.py" > /tmp/or_py.txt
	grep '^REF' /tmp/or_c.txt > /tmp/or_c_ref.txt
	if diff -q /tmp/or_c_ref.txt /tmp/or_py.txt >/dev/null; then
		echo "    MATCH: write-only ORAM (real chacha/Sha2 objects) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/or_c_ref.txt /tmp/or_py.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/or_c.txt; then echo "    ORAM POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/or_log)"
fi

echo ""
echo "[14] Decoy-fragments-by-default: real hidden header vs decoy fragment are indistinguishable-random"
# A real hidden-volume header (salt||ChaCha20-encrypted) and a decoy fragment (salt||keystream) are the
# same uniform distribution, so a free-space scanner can't tell a with-hidden volume from a decoy one.
# Links the REAL in-tree chacha256.c; decoyfrag_reference.py is the independent reference.
DF_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then DF_CC="$c"; break; fi; done
DF_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
DF_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
DF_GC="-ffunction-sections -fdata-sections"
DF_INC="$INC -I$SRCROOT/Crypto"
if "$DF_CC" -O2 $DF_WNO $DF_NOASM $DF_GC $DF_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/df_cc.o 2>/tmp/df_log \
   && "$DF_CC" -O2 $DF_WNO $DF_NOASM $DF_INC "$HERE/decoyfrag_poc.c" /tmp/df_cc.o -Wl,--gc-sections -o /tmp/decoyfrag_poc 2>>/tmp/df_log; then
	/tmp/decoyfrag_poc > /tmp/df_c.txt; cat /tmp/df_c.txt
	python3 "$HERE/decoyfrag_reference.py" > /tmp/df_py.txt
	grep '^REF' /tmp/df_c.txt > /tmp/df_c_ref.txt
	grep '^REF' /tmp/df_py.txt > /tmp/df_py_ref.txt
	if diff -q /tmp/df_c_ref.txt /tmp/df_py_ref.txt >/dev/null; then
		echo "    MATCH: decoy fragment generator (real chacha) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/df_c_ref.txt /tmp/df_py_ref.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/df_c.txt; then echo "    DECOYFRAG POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/df_log)"
fi

echo ""
echo "[15] Anti-forensic key splitting (SSD-remnant answer): split/merge + partial-recovery-defeated"
# LUKS/TKS1 AFsplit: diffuse a wrapped key across s stripes so recovery needs ALL of them; any missing
# stripe (an SSD wear-leveling remnant) yields nothing. Links the REAL in-tree Sha2.c; afsplit_reference.py
# is the independent reference (hashlib).
AF_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then AF_CC="$c"; break; fi; done
AF_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
AF_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
AF_GC="-ffunction-sections -fdata-sections"
AF_INC="$INC -I$SRCROOT/Crypto"
if "$AF_CC" -O2 $AF_WNO $AF_NOASM $AF_GC $AF_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/af_sha2.o 2>/tmp/af_log \
   && "$AF_CC" -O2 $AF_WNO $AF_NOASM $AF_INC "$HERE/afsplit_poc.c" /tmp/af_sha2.o -Wl,--gc-sections -o /tmp/afsplit_poc 2>>/tmp/af_log; then
	/tmp/afsplit_poc > /tmp/af_c.txt; cat /tmp/af_c.txt
	python3 "$HERE/afsplit_reference.py" > /tmp/af_py.txt
	grep '^REF' /tmp/af_c.txt > /tmp/af_c_ref.txt; grep '^REF' /tmp/af_py.txt > /tmp/af_py_ref.txt
	if diff -q /tmp/af_c_ref.txt /tmp/af_py_ref.txt >/dev/null; then
		echo "    MATCH: AF split/merge (real Sha2 object) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/af_c_ref.txt /tmp/af_py_ref.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/af_c.txt; then echo "    AFSPLIT POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/af_log)"
fi

echo ""
echo "[16] Balloon memory-hard KDF (candidate alongside Argon2id) vs independent python"
# Balloon (Boneh-Corrigan-Gibbs-Schechter) over the in-tree SHA-256: expand/mix(delta=3)/extract with
# explicit space + time cost. Links the REAL in-tree Sha2.c; balloon_reference.py is independent (hashlib).
BL_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then BL_CC="$c"; break; fi; done
BL_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
BL_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
BL_GC="-ffunction-sections -fdata-sections"
BL_INC="$INC -I$SRCROOT/Crypto"
if "$BL_CC" -O2 $BL_WNO $BL_NOASM $BL_GC $BL_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/bl_sha2.o 2>/tmp/bl_log \
   && "$BL_CC" -O2 $BL_WNO $BL_NOASM $BL_INC "$HERE/balloon_poc.c" /tmp/bl_sha2.o -Wl,--gc-sections -o /tmp/balloon_poc 2>>/tmp/bl_log; then
	/tmp/balloon_poc > /tmp/bl_c.txt; cat /tmp/bl_c.txt
	python3 "$HERE/balloon_reference.py" > /tmp/bl_py.txt
	grep '^REF' /tmp/bl_c.txt > /tmp/bl_c_ref.txt; grep '^REF' /tmp/bl_py.txt > /tmp/bl_py_ref.txt
	if diff -q /tmp/bl_c_ref.txt /tmp/bl_py_ref.txt >/dev/null; then
		echo "    MATCH: Balloon KDF (real Sha2 object) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/bl_c_ref.txt /tmp/bl_py_ref.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/bl_c.txt; then echo "    BALLOON POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/bl_log)"
fi

echo ""
echo "[17] OPRF password hardening (offline-guessing resistant, server never sees pw) vs independent python"
# 2HashDH / CFRG DH-OPRF: derived key depends on the password AND a server secret; the server sees only
# a blinded value. Links the REAL in-tree Sha2.c; oprf_reference.py is independent (python bigint).
OP_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then OP_CC="$c"; break; fi; done
OP_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
OP_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
OP_GC="-ffunction-sections -fdata-sections"
OP_INC="$INC -I$SRCROOT/Crypto"
if "$OP_CC" -O2 $OP_WNO $OP_NOASM $OP_GC $OP_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/op_sha2.o 2>/tmp/op_log \
   && "$OP_CC" -O2 $OP_WNO $OP_NOASM $OP_INC "$HERE/oprf_poc.c" /tmp/op_sha2.o -Wl,--gc-sections -o /tmp/oprf_poc 2>>/tmp/op_log; then
	/tmp/oprf_poc > /tmp/op_c.txt; cat /tmp/op_c.txt
	python3 "$HERE/oprf_reference.py" > /tmp/op_py.txt
	grep '^REF' /tmp/op_c.txt > /tmp/op_c_ref.txt; grep '^REF' /tmp/op_py.txt > /tmp/op_py_ref.txt
	if diff -q /tmp/op_c_ref.txt /tmp/op_py_ref.txt >/dev/null; then
		echo "    MATCH: OPRF (real Sha2 object) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/op_c_ref.txt /tmp/op_py_ref.txt; exit 1
	fi
	if grep -Eq ': NO$' /tmp/op_c.txt; then echo "    OPRF POC FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/op_log)"
fi

echo "[18] Poly1305 one-shot (RFC 8439) vs independent python reference + published KATs"
# Poly1305 is NOT in the VeraCrypt tree, so there is no in-tree object to link. It is proven the two
# independent ways this fork requires: (a) poly1305_poc.c (radix-2^26) == poly1305_reference.py (bigint)
# byte-for-byte over the RFC KATs plus a deterministic fuzz battery, and (b) both reproduce the RFC 8439
# published tags (Sec 2.5.2 and A.3). Candidate for the integrity tier / wide-block modes; see docs/POLY1305-SPEC.md.
PL_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then PL_CC="$c"; break; fi; done
if "$PL_CC" -O2 -Wall -I"$HERE" "$HERE/poly1305_poc.c" -o /tmp/poly1305_poc 2>/tmp/pl_log; then
	/tmp/poly1305_poc > /tmp/pl_c.txt; sed -n '1,3p' /tmp/pl_c.txt
	python3 "$HERE/poly1305_reference.py" > /tmp/pl_py.txt
	grep '^REF' /tmp/pl_c.txt > /tmp/pl_c_ref.txt; grep '^REF' /tmp/pl_py.txt > /tmp/pl_py_ref.txt
	if diff -q /tmp/pl_c_ref.txt /tmp/pl_py_ref.txt >/dev/null; then
		echo "    MATCH: Poly1305 C (radix-2^26) == python bigint over $(wc -l < /tmp/pl_c_ref.txt) vectors (3 KAT + fuzz)"
	else
		echo "    MISMATCH"; diff /tmp/pl_c_ref.txt /tmp/pl_py_ref.txt; exit 1
	fi
	# assert the two RFC 8439 published tags explicitly
	grep -q '^REF rfc_2.5.2 a8061dc1305136c6c22b8baf0c0127a9$' /tmp/pl_c.txt || { echo "    RFC 2.5.2 KAT FAILED"; exit 1; }
	grep -q '^REF a3_1 36e5f6b5c5e06070f0efca96227a863e$'   /tmp/pl_c.txt || { echo "    RFC A.3 #2 KAT FAILED"; exit 1; }
	echo "    RFC 8439 published tags reproduced (Sec 2.5.2 + A.3)"
else
	skip_step " no compiler available (see /tmp/pl_log)"
fi

echo "[19] Merkle tree over the volume, root held off-disk (tamper detection) vs independent python"
# Binary hash tree over sectors; a trusted off-disk root detects any offline modification XTS cannot.
# RFC 6962 domain separation (leaf 0x00||i||data, node 0x01||l||r); O(log N) authentication paths.
# Links the REAL in-tree Sha2.c; merkle_reference.py is independent (hashlib). See docs/MERKLE-SPEC.md.
MK_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then MK_CC="$c"; break; fi; done
MK_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
MK_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
MK_GC="-ffunction-sections -fdata-sections"
MK_INC="$INC -I$SRCROOT/Crypto"
if "$MK_CC" -O2 $MK_WNO $MK_NOASM $MK_GC $MK_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/mk_sha2.o 2>/tmp/mk_log \
   && "$MK_CC" -O2 $MK_WNO $MK_NOASM $MK_INC "$HERE/merkle_poc.c" /tmp/mk_sha2.o -Wl,--gc-sections -o /tmp/merkle_poc 2>>/tmp/mk_log; then
	/tmp/merkle_poc > /tmp/mk_c.txt; grep -E '^REF (root|tamper)' /tmp/mk_c.txt
	python3 "$HERE/merkle_reference.py" > /tmp/mk_py.txt
	grep '^REF' /tmp/mk_c.txt > /tmp/mk_c_ref.txt; grep '^REF' /tmp/mk_py.txt > /tmp/mk_py_ref.txt
	if diff -q /tmp/mk_c_ref.txt /tmp/mk_py_ref.txt >/dev/null; then
		echo "    MATCH: Merkle (real Sha2 object) == independent python over $(wc -l < /tmp/mk_c_ref.txt) vectors (root + auth paths + tamper)"
	else
		echo "    MISMATCH"; diff /tmp/mk_c_ref.txt /tmp/mk_py_ref.txt; exit 1
	fi
	grep -q '^REF tamper_detected YES$'      /tmp/mk_c.txt || { echo "    TAMPER NOT DETECTED"; exit 1; }
	grep -q '^REF tamper_path_rejected YES$' /tmp/mk_c.txt || { echo "    STALE PROOF ACCEPTED"; exit 1; }
	echo "    single-bit sector flip changes the root and its authentication path is rejected"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/mk_log)"
fi

echo "[20] Keyslot-area MAC (ChaCha20-Poly1305 one-time) — tamper/truncation detection vs independent python"
# Authenticate the keyslot table under a key derived from the master key: one_time_key = ChaCha20(mac_key,
# nonce)[0..32], tag = Poly1305(otk, area). Any edit/truncation/slot-count change fails a constant-time
# check before unwrap. Links the REAL in-tree chacha256.c + the step-18 Poly1305; python is independent
# (pure-python ChaCha + bigint Poly1305). No on-disk format change. See docs/KEYSLOT-MAC-SPEC.md.
KM_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KM_CC="$c"; break; fi; done
KM_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
KM_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KM_GC="-ffunction-sections -fdata-sections"
KM_INC="$INC -I$SRCROOT/Crypto"
if "$KM_CC" -O2 $KM_WNO $KM_NOASM $KM_GC $KM_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/km_cc.o 2>/tmp/km_log \
   && "$KM_CC" -O2 $KM_WNO $KM_NOASM $KM_INC "$HERE/keyslot_mac_poc.c" /tmp/km_cc.o -Wl,--gc-sections -o /tmp/km_poc 2>>/tmp/km_log; then
	/tmp/km_poc > /tmp/km_c.txt; grep -E '^REF (mac|accept|reject|nonce|chacha)' /tmp/km_c.txt
	python3 "$HERE/keyslot_mac_reference.py" > /tmp/km_py.txt
	grep '^REF' /tmp/km_c.txt > /tmp/km_c_ref.txt; grep '^REF' /tmp/km_py.txt > /tmp/km_py_ref.txt
	if diff -q /tmp/km_c_ref.txt /tmp/km_py_ref.txt >/dev/null; then
		echo "    MATCH: keyslot-area MAC (real chacha256 + Poly1305) == independent python over $(wc -l < /tmp/km_c_ref.txt) vectors"
	else
		echo "    MISMATCH"; diff /tmp/km_c_ref.txt /tmp/km_py_ref.txt; exit 1
	fi
	grep -q '^REF chacha_zero_kat 76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7$' /tmp/km_c.txt || { echo "    CHACHA KAT FAILED"; exit 1; }
	for k in accept_valid reject_tamper reject_trunc reject_wrongkey nonce_binds; do
		grep -q "^REF $k YES$" /tmp/km_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    tamper, truncation, wrong-key all rejected by constant-time tag check; nonce binds"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/km_log)"
fi

echo "[21] Per-sector authentication (dm-integrity style) — tamper/relocation detection vs independent python"
# One Poly1305 tag per sector over the ciphertext, bound to the sector index (nonce = index): per-sector
# independence + relocation resistance a whole-area MAC cannot give. Links the REAL in-tree chacha256.c +
# the step-18 Poly1305; persector_reference.py is independent. TAG STORAGE is [FORMAT]. See docs/PERSECTOR-AUTH-SPEC.md.
PS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then PS_CC="$c"; break; fi; done
PS_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
PS_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
PS_GC="-ffunction-sections -fdata-sections"
PS_INC="$INC -I$SRCROOT/Crypto"
if "$PS_CC" -O2 $PS_WNO $PS_NOASM $PS_GC $PS_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ps_cc.o 2>/tmp/ps_log \
   && "$PS_CC" -O2 $PS_WNO $PS_NOASM $PS_INC "$HERE/persector_poc.c" /tmp/ps_cc.o -Wl,--gc-sections -o /tmp/ps_poc 2>>/tmp/ps_log; then
	/tmp/ps_poc > /tmp/ps_c.txt; grep -E '^REF (accept|tamper|relocation|wrongkey)' /tmp/ps_c.txt
	python3 "$HERE/persector_reference.py" > /tmp/ps_py.txt
	grep '^REF' /tmp/ps_c.txt > /tmp/ps_c_ref.txt; grep '^REF' /tmp/ps_py.txt > /tmp/ps_py_ref.txt
	if diff -q /tmp/ps_c_ref.txt /tmp/ps_py_ref.txt >/dev/null; then
		echo "    MATCH: per-sector auth (real chacha256 + Poly1305) == independent python over $(wc -l < /tmp/ps_c_ref.txt) vectors"
	else
		echo "    MISMATCH"; diff /tmp/ps_c_ref.txt /tmp/ps_py_ref.txt; exit 1
	fi
	for k in accept_all tamper_only_5_fails relocation_detected wrongkey_detected; do
		grep -q "^REF $k YES$" /tmp/ps_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    per-sector independence, relocation resistance, and wrong-key all hold"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ps_log)"
fi

echo "[22] Rollback/replay protection via a monotonic counter — snapshot-replay detection vs independent python"
# Bind a hardware monotonic counter (TPM NV / token) into the top-level commit authenticator:
# otk = ChaCha20(commit_key, le64(counter))[0..32], tag = Poly1305(otk, state_root). A restored older
# snapshot carries an old counter and fails vs the advanced hardware counter -- the replay that Merkle/
# per-sector MACs cannot catch. Links the REAL in-tree chacha256.c + step-18 Poly1305. See docs/ROLLBACK-COUNTER-SPEC.md.
MC_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then MC_CC="$c"; break; fi; done
MC_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
MC_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
MC_GC="-ffunction-sections -fdata-sections"
MC_INC="$INC -I$SRCROOT/Crypto"
if "$MC_CC" -O2 $MC_WNO $MC_NOASM $MC_GC $MC_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/mc_cc.o 2>/tmp/mc_log \
   && "$MC_CC" -O2 $MC_WNO $MC_NOASM $MC_INC "$HERE/monotcounter_poc.c" /tmp/mc_cc.o -Wl,--gc-sections -o /tmp/mc_poc 2>>/tmp/mc_log; then
	/tmp/mc_poc > /tmp/mc_c.txt; grep -E '^REF (fresh|rollback|forged|tamper|monotonic|wrongkey)' /tmp/mc_c.txt
	python3 "$HERE/monotcounter_reference.py" > /tmp/mc_py.txt
	grep '^REF' /tmp/mc_c.txt > /tmp/mc_c_ref.txt; grep '^REF' /tmp/mc_py.txt > /tmp/mc_py_ref.txt
	if diff -q /tmp/mc_c_ref.txt /tmp/mc_py_ref.txt >/dev/null; then
		echo "    MATCH: rollback counter (real chacha256 + Poly1305) == independent python over $(wc -l < /tmp/mc_c_ref.txt) vectors"
	else
		echo "    MISMATCH"; diff /tmp/mc_c_ref.txt /tmp/mc_py_ref.txt; exit 1
	fi
	for k in fresh_accept rollback_detected forged_marker_detected tamper_state_detected monotonic_enforced wrongkey_detected; do
		grep -q "^REF $k YES$" /tmp/mc_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    snapshot rollback + forged marker + tamper rejected; counter is increment-only"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/mc_log)"
fi

echo "[23] Header-version + anti-downgrade parameter binding — reject silent parameter downgrade vs independent python"
# Bind a canonical fixed-width serialization of every KDF/cipher parameter (version, prf/cipher/mode ids,
# Argon2 mem/iters/parallelism) into an HMAC keyed from the password. Any header edit that weakens a
# parameter changes the tag -> fail closed, not silent-weak-derive. Links the REAL in-tree Sha2.c;
# downgrade_reference.py is independent (hashlib). See docs/ANTI-DOWNGRADE-SPEC.md.
DG_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then DG_CC="$c"; break; fi; done
DG_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
DG_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
DG_GC="-ffunction-sections -fdata-sections"
DG_INC="$INC -I$SRCROOT/Crypto"
if "$DG_CC" -O2 $DG_WNO $DG_NOASM $DG_GC $DG_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/dg_sha2.o 2>/tmp/dg_log \
   && "$DG_CC" -O2 $DG_WNO $DG_NOASM $DG_INC "$HERE/downgrade_poc.c" /tmp/dg_sha2.o -Wl,--gc-sections -o /tmp/dg_poc 2>>/tmp/dg_log; then
	/tmp/dg_poc > /tmp/dg_c.txt; grep -E '^REF (accept|all_downgrades|wrongpw|canon_un)' /tmp/dg_c.txt
	python3 "$HERE/downgrade_reference.py" > /tmp/dg_py.txt
	grep '^REF' /tmp/dg_c.txt > /tmp/dg_c_ref.txt; grep '^REF' /tmp/dg_py.txt > /tmp/dg_py_ref.txt
	if diff -q /tmp/dg_c_ref.txt /tmp/dg_py_ref.txt >/dev/null; then
		echo "    MATCH: parameter binding (real Sha2 object) == independent python over $(wc -l < /tmp/dg_c_ref.txt) vectors"
	else
		echo "    MISMATCH"; diff /tmp/dg_c_ref.txt /tmp/dg_py_ref.txt; exit 1
	fi
	for k in accept_base all_downgrades_detected wrongpw_detected canon_unambiguous; do
		grep -q "^REF $k YES$" /tmp/dg_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    every Argon2/PRF/cipher/version downgrade rejected; canonical encoding unambiguous"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/dg_log)"
fi

echo "[24] Adiantum wide-block mode (XChaCha12/AES-256/NH/Poly1305) — official google/adiantum KATs vs independent python"
# The single strongest cryptographic upgrade for a disk encryptor (IDEAS-BACKLOG B): a length-preserving
# tweakable super-pseudorandom permutation over the whole sector, killing XTS's 16-byte malleability --
# flipping any ciphertext bit randomizes the entire sector. Links the REAL in-tree chacha256.c (all
# ChaCha keystream) + Aescrypt/Aeskey/Aestab.c (AES-256) + the step-18 Poly1305; adiantum_reference.py
# is independent (pure python, incl. its own AES). Arbiter: 18 official vectors (adiantum_kats.{h,py})
# covering message lengths 16..4096 x tweak lengths 0/17/32. See docs/ADIANTUM-SPEC.md.
AD_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then AD_CC="$c"; break; fi; done
AD_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
AD_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
AD_INC="$INC -I$SRCROOT/Crypto"
if "$AD_CC" -O2 $AD_WNO $AD_NOASM $AD_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ad_chacha.o 2>/tmp/ad_log \
   && "$AD_CC" -O2 $AD_WNO $AD_NOASM $AD_INC -c "$SRCROOT/Crypto/Aescrypt.c" -o /tmp/ad_aescrypt.o 2>>/tmp/ad_log \
   && "$AD_CC" -O2 $AD_WNO $AD_NOASM $AD_INC -c "$SRCROOT/Crypto/Aeskey.c" -o /tmp/ad_aeskey.o 2>>/tmp/ad_log \
   && "$AD_CC" -O2 $AD_WNO $AD_NOASM $AD_INC -c "$SRCROOT/Crypto/Aestab.c" -o /tmp/ad_aestab.o 2>>/tmp/ad_log \
   && "$AD_CC" -O2 $AD_WNO $AD_NOASM $AD_INC "$HERE/adiantum_poc.c" /tmp/ad_chacha.o /tmp/ad_aescrypt.o /tmp/ad_aeskey.o /tmp/ad_aestab.o -o /tmp/adiantum_poc 2>>/tmp/ad_log; then
	/tmp/adiantum_poc > /tmp/ad_c.txt || { echo "    ADIANTUM POC FAILED"; grep -vE '^REF kat_[0-9]' /tmp/ad_c.txt; exit 1; }
	grep -vE '^REF kat_[0-9]' /tmp/ad_c.txt
	( cd "$HERE" && python3 adiantum_reference.py ) > /tmp/ad_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/ad_c.txt > /tmp/ad_c_ref.txt; grep '^REF' /tmp/ad_py.txt > /tmp/ad_py_ref.txt
	if diff -q /tmp/ad_c_ref.txt /tmp/ad_py_ref.txt >/dev/null; then
		echo "    MATCH: Adiantum (real chacha256+AES objects) == independent python over $(wc -l < /tmp/ad_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/ad_c_ref.txt /tmp/ad_py_ref.txt | head -6; exit 1
	fi
	for k in kat_all_match roundtrip_all enc_diffusion dec_diffusion wrongkey wrongtweak; do
		grep -q "^REF $k YES$" /tmp/ad_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	grep -q '^REF aes256_fips197 8ea2b7ca516745bfeafc49904b496089$' /tmp/ad_c.txt || { echo "    AES FIPS-197 KAT FAILED"; exit 1; }
	echo "    all 18 official vectors reproduced; single-bit flip randomizes the whole sector"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ad_log)"
fi

echo "[25] ML-KEM-768 (FIPS 203) + PQ hybrid combiner — NIST ACVP vectors vs independent python"
# Post-quantum hybrid for the asymmetric exchanges (IDEAS-BACKLOG H): the network-share / OPRF DH is
# harvest-now-decrypt-later quantum-breakable; ML-KEM-768 + the classical secret feed one HMAC combiner
# so a break of EITHER component alone does not reveal the key. C PoC implements FIPS 203 with a local
# Keccak ANCHORED to the real in-tree Sha3.c (CHK line) and uses the real Sha2.c for the combiner;
# mlkem_reference.py is independent (hashlib). Arbiter: NIST ACVP vectors (mlkem_kats.{h,py}) incl. 5
# modified-ciphertext implicit-rejection decaps cases. See docs/PQ-HYBRID-SPEC.md.
MK2_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then MK2_CC="$c"; break; fi; done
MK2_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
MK2_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
MK2_GC="-ffunction-sections -fdata-sections"
MK2_INC="$INC -I$SRCROOT/Crypto"
if "$MK2_CC" -O2 $MK2_WNO $MK2_NOASM $MK2_GC $MK2_INC -c "$SRCROOT/Crypto/Sha3.c" -o /tmp/mk_sha3.o 2>/tmp/mk2_log \
   && "$MK2_CC" -O2 $MK2_WNO $MK2_NOASM $MK2_GC $MK2_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/mk_sha2.o 2>>/tmp/mk2_log \
   && "$MK2_CC" -O2 $MK2_WNO $MK2_NOASM $MK2_INC "$HERE/mlkem_poc.c" /tmp/mk_sha3.o /tmp/mk_sha2.o -Wl,--gc-sections -o /tmp/mlkem_poc 2>>/tmp/mk2_log; then
	/tmp/mlkem_poc > /tmp/mk2_c.txt || { echo "    MLKEM POC FAILED"; grep -E '^CHK|match|hybrid' /tmp/mk2_c.txt; exit 1; }
	grep -E '^CHK|all_match|implicit|hybrid' /tmp/mk2_c.txt
	( cd "$HERE" && python3 mlkem_reference.py ) > /tmp/mk2_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/mk2_c.txt > /tmp/mk2_c_ref.txt; grep '^REF' /tmp/mk2_py.txt > /tmp/mk2_py_ref.txt
	if diff -q /tmp/mk2_c_ref.txt /tmp/mk2_py_ref.txt >/dev/null; then
		echo "    MATCH: ML-KEM-768 (in-tree-anchored Keccak + real Sha2) == independent python over $(wc -l < /tmp/mk2_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/mk2_c_ref.txt /tmp/mk2_py_ref.txt | head -6; exit 1
	fi
	for k in keygen_all_match encaps_all_match decaps_all_match hybrid_needs_both; do
		grep -q "^REF $k YES$" /tmp/mk2_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	grep -q '^REF implicit_rejection_cases 5$' /tmp/mk2_c.txt || { echo "    IMPLICIT-REJECTION COUNT WRONG"; exit 1; }
	grep -q '^CHK sha3_512_intree_match YES$' /tmp/mk2_c.txt || { echo "    IN-TREE SHA3 ANCHOR FAILED"; exit 1; }
	echo "    NIST ACVP vectors reproduced incl. implicit rejection; hybrid needs both secrets"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/mk2_log)"
fi

echo "[26] HCTR2 wide-block mode (XCTR + POLYVAL) — official google/hctr2 KATs vs independent python"
# The AES-NI-era sibling of Adiantum (IDEAS-BACKLOG B; shipped in the Linux kernel for fscrypt):
# tweakable SPRP over the whole sector from AES-256 XCTR + POLYVAL (RFC 8452). Links the REAL in-tree
# Aescrypt/Aeskey/Aestab.c (FIPS-197 KAT asserted); POLYVAL is PoC-local, anchored to the RFC 8452
# published example (no POLYVAL in the VeraCrypt tree). Arbiter: 35 official vectors (hctr2_kats.{h,py})
# covering message lengths 16..512 x tweak lengths 0/1/16/32/47. See docs/HCTR2-SPEC.md.
H2_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then H2_CC="$c"; break; fi; done
H2_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
H2_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
H2_INC="$INC -I$SRCROOT/Crypto"
if "$H2_CC" -O2 $H2_WNO $H2_NOASM $H2_INC -c "$SRCROOT/Crypto/Aescrypt.c" -o /tmp/h2_aescrypt.o 2>/tmp/h2_log \
   && "$H2_CC" -O2 $H2_WNO $H2_NOASM $H2_INC -c "$SRCROOT/Crypto/Aeskey.c" -o /tmp/h2_aeskey.o 2>>/tmp/h2_log \
   && "$H2_CC" -O2 $H2_WNO $H2_NOASM $H2_INC -c "$SRCROOT/Crypto/Aestab.c" -o /tmp/h2_aestab.o 2>>/tmp/h2_log \
   && "$H2_CC" -O2 $H2_WNO $H2_NOASM $H2_INC "$HERE/hctr2_poc.c" /tmp/h2_aescrypt.o /tmp/h2_aeskey.o /tmp/h2_aestab.o -o /tmp/hctr2_poc 2>>/tmp/h2_log; then
	/tmp/hctr2_poc > /tmp/h2_c.txt || { echo "    HCTR2 POC FAILED"; grep -vE '^REF kat_[0-9]' /tmp/h2_c.txt; exit 1; }
	grep -vE '^REF kat_[0-9]' /tmp/h2_c.txt
	( cd "$HERE" && python3 hctr2_reference.py ) > /tmp/h2_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/h2_c.txt > /tmp/h2_c_ref.txt; grep '^REF' /tmp/h2_py.txt > /tmp/h2_py_ref.txt
	if diff -q /tmp/h2_c_ref.txt /tmp/h2_py_ref.txt >/dev/null; then
		echo "    MATCH: HCTR2 (real AES objects) == independent python over $(wc -l < /tmp/h2_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/h2_c_ref.txt /tmp/h2_py_ref.txt | head -6; exit 1
	fi
	for k in kat_all_match roundtrip_all enc_diffusion dec_diffusion wrongkey wrongtweak; do
		grep -q "^REF $k YES$" /tmp/h2_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	grep -q '^REF aes256_fips197 8ea2b7ca516745bfeafc49904b496089$' /tmp/h2_c.txt || { echo "    AES FIPS-197 KAT FAILED"; exit 1; }
	grep -q '^REF polyval_rfc8452 f7a3b47b846119fae5b7866cf5e5b77e$' /tmp/h2_c.txt || { echo "    POLYVAL RFC-8452 KAT FAILED"; exit 1; }
	echo "    all 35 official vectors reproduced; single-bit flip randomizes the whole sector"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/h2_log)"
fi

echo "[27] BLAKE3 tree hash — official published vectors vs independent python"
# Fast tree/parallel hash (IDEAS-BACKLOG "Hashes" row): 7-round BLAKE2s-style compression, 1024-byte
# chunks, po2-left binary tree, keyed + derive-key modes, XOF. Candidate fast keyfile/pool hash and
# Merkle tree hash. NOT in the VeraCrypt tree (like Poly1305): proof = the official BLAKE3-team vectors
# (blake3_kats.{h,py}, all 35 cases x 3 modes x 131-byte XOF) + byte-identical C/python REF output.
B3_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then B3_CC="$c"; break; fi; done
if "$B3_CC" -O2 -Wall -I"$HERE" "$HERE/blake3_poc.c" -o /tmp/blake3_poc 2>/tmp/b3_log; then
	/tmp/blake3_poc > /tmp/b3_c.txt || { echo "    BLAKE3 POC FAILED"; tail -2 /tmp/b3_c.txt; exit 1; }
	( cd "$HERE" && python3 blake3_reference.py ) > /tmp/b3_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/b3_c.txt > /tmp/b3_c_ref.txt; grep '^REF' /tmp/b3_py.txt > /tmp/b3_py_ref.txt
	if diff -q /tmp/b3_c_ref.txt /tmp/b3_py_ref.txt >/dev/null; then
		echo "    MATCH: BLAKE3 C == independent python over $(wc -l < /tmp/b3_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/b3_c_ref.txt /tmp/b3_py_ref.txt | head -4; exit 1
	fi
	grep -q '^REF all_match YES$' /tmp/b3_c.txt || { echo "    OFFICIAL VECTORS FAILED"; exit 1; }
	echo "    all 35 official cases (hash/keyed/derive_key, 0..102400 B, 131-B XOF) reproduced"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler (see /tmp/b3_log)"
fi

echo "[28] Ascon-Hash256 (NIST SP 800-232) — official NIST ACVP vectors vs independent python"
# The NIST Lightweight Cryptography winner (IDEAS-BACKLOG "Hashes" row): 320-bit state, 12-round
# permutation, rate 8; compact hash for constrained targets. NOT in the VeraCrypt tree: proof = the
# official NIST ACVP SP 800-232 vectors (ascon_kats.{h,py}) + byte-identical C/python REF output.
AS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then AS_CC="$c"; break; fi; done
if "$AS_CC" -O2 -Wall -I"$HERE" "$HERE/ascon_poc.c" -o /tmp/ascon_poc 2>/tmp/as_log; then
	/tmp/ascon_poc > /tmp/as_c.txt || { echo "    ASCON POC FAILED"; tail -2 /tmp/as_c.txt; exit 1; }
	( cd "$HERE" && python3 ascon_reference.py ) > /tmp/as_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/as_c.txt > /tmp/as_c_ref.txt; grep '^REF' /tmp/as_py.txt > /tmp/as_py_ref.txt
	if diff -q /tmp/as_c_ref.txt /tmp/as_py_ref.txt >/dev/null; then
		echo "    MATCH: Ascon-Hash256 C == independent python over $(wc -l < /tmp/as_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/as_c_ref.txt /tmp/as_py_ref.txt | head -4; exit 1
	fi
	grep -q '^REF all_match YES$' /tmp/as_c.txt || { echo "    OFFICIAL VECTORS FAILED"; exit 1; }
	echo "    all official NIST ACVP Ascon-Hash256 vectors reproduced"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler (see /tmp/as_log)"
fi

echo "[29] Threefish large-block cipher (512 + 1024) — official Botan-512 vectors vs independent python"
# Large-block cipher (IDEAS-BACKLOG "Large-block ciphers" row): Threefish's 1024-bit block gives ~2^64x
# the birthday-bound headroom of AES-128 for very large volumes. Threefish-512 anchored to the OFFICIAL
# Botan published vectors (threefish_kats.{h,py}) which pin the MIX/rotation/key-schedule/permute
# machinery; Threefish-1024 (same construction, own rotation table) proven by C==python + round-trip.
# NOT in the VeraCrypt tree. See docs/LARGE-BLOCK-SPEC.md.
TF_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then TF_CC="$c"; break; fi; done
if "$TF_CC" -O2 -Wall -I"$HERE" "$HERE/threefish_poc.c" -o /tmp/threefish_poc 2>/tmp/tf_log; then
	/tmp/threefish_poc > /tmp/tf_c.txt || { echo "    THREEFISH POC FAILED"; grep -vE '^REF tf512_[0-9]' /tmp/tf_c.txt; exit 1; }
	grep -vE '^REF tf512_[0-9]' /tmp/tf_c.txt
	( cd "$HERE" && python3 threefish_reference.py ) > /tmp/tf_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/tf_c.txt > /tmp/tf_c_ref.txt; grep '^REF' /tmp/tf_py.txt > /tmp/tf_py_ref.txt
	if diff -q /tmp/tf_c_ref.txt /tmp/tf_py_ref.txt >/dev/null; then
		echo "    MATCH: Threefish C == independent python over $(wc -l < /tmp/tf_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/tf_c_ref.txt /tmp/tf_py_ref.txt | head -4; exit 1
	fi
	for k in tf512_official_match tf1024_roundtrip tf512_roundtrip; do
		grep -q "^REF $k YES$" /tmp/tf_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    Threefish-512 matches official Botan vectors; 1024 cross-checked + round-trips"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler (see /tmp/tf_log)"
fi

echo "[30] Sloth verifiable delay function (coercion cooling-off) — C bignum vs independent python"
# Delay functions row (IDEAS-BACKLOG): Sloth (Lenstra-Wesolowski) -- T sequential modular-sqrt steps to
# compute (each a modexp), T cheap squarings to verify. Unparallelizable delay + instant check = a
# coercion cooling-off factor. No standard KAT; proof = byte-identical C(256-bit bignum) vs python +
# the defining invertibility (verify recovers seed) + tamper detection. See docs/DELAY-SPEC.md.
SL_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SL_CC="$c"; break; fi; done
if "$SL_CC" -O2 -Wall -I"$HERE" "$HERE/sloth_poc.c" -o /tmp/sloth_poc 2>/tmp/sl_log; then
	/tmp/sloth_poc > /tmp/sl_c.txt || { echo "    SLOTH POC FAILED"; cat /tmp/sl_c.txt; exit 1; }
	cat /tmp/sl_c.txt
	( cd "$HERE" && python3 sloth_reference.py ) > /tmp/sl_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/sl_c.txt > /tmp/sl_c_ref.txt; grep '^REF' /tmp/sl_py.txt > /tmp/sl_py_ref.txt
	if diff -q /tmp/sl_c_ref.txt /tmp/sl_py_ref.txt >/dev/null; then
		echo "    MATCH: Sloth C (256-bit bignum) == independent python over $(wc -l < /tmp/sl_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/sl_c_ref.txt /tmp/sl_py_ref.txt | head -4; exit 1
	fi
	for k in verify_recovers_seed deterministic steps_matter tamper_detected; do
		grep -q "^REF $k YES$" /tmp/sl_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    delay chain verifies (fast squarings recover the seed); tamper detected"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler (see /tmp/sl_log)"
fi

echo "[31] Feldman verifiable secret sharing — C bignum vs independent python"
# Sharing row (IDEAS-BACKLOG): Feldman VSS adds dealer-verifiability to Shamir (step [5]) -- coefficient
# commitments C_j=g^{a_j} let each holder check its share without learning the secret, catching a cheating
# dealer at distribution. No standard KAT; proof = byte-identical C(256-bit bignum, order-q subgroup) vs
# python + the verifiability properties (honest verify, tamper rejected, t reconstruct). docs/VSS-SPEC.md
FV_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then FV_CC="$c"; break; fi; done
if "$FV_CC" -O2 -Wall -I"$HERE" "$HERE/feldman_poc.c" -o /tmp/feldman_poc 2>/tmp/fv_log; then
	/tmp/feldman_poc > /tmp/fv_c.txt || { echo "    FELDMAN POC FAILED"; grep -vE '^REF (commit|share)_' /tmp/fv_c.txt; exit 1; }
	grep -vE '^REF (commit|share)_[0-9]' /tmp/fv_c.txt
	( cd "$HERE" && python3 feldman_reference.py ) > /tmp/fv_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/fv_c.txt > /tmp/fv_c_ref.txt; grep '^REF' /tmp/fv_py.txt > /tmp/fv_py_ref.txt
	if diff -q /tmp/fv_c_ref.txt /tmp/fv_py_ref.txt >/dev/null; then
		echo "    MATCH: Feldman VSS C (256-bit bignum) == independent python over $(wc -l < /tmp/fv_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/fv_c_ref.txt /tmp/fv_py_ref.txt | head -4; exit 1
	fi
	for k in all_shares_verify tampered_share_rejected reconstruct_t below_threshold_wrong; do
		grep -q "^REF $k YES$" /tmp/fv_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    commitments verify honest shares, reject a tampered share; t-of-n reconstructs"
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler (see /tmp/fv_log)"
fi

echo "[32] Pedersen verifiable secret sharing (perfectly hiding) — C bignum vs independent python"
# Sharing row (IDEAS-BACKLOG): Pedersen VSS blinds Feldman's commitments (step [31]) with a second
# generator h so they are PERFECTLY hiding, not just computationally. C_j = g^{a_j} h^{b_j}; each holder
# checks g^{f(i)} h^{b(i)} == prod C_j^{i^j}. No standard KAT; proof = byte-identical C(256-bit bignum)
# vs python + verifiability (honest verify, tampered f OR b rejected, t reconstruct). docs/VSS-SPEC.md
PD_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then PD_CC="$c"; break; fi; done
if "$PD_CC" -O2 -Wall -I"$HERE" "$HERE/pedersen_poc.c" -o /tmp/pedersen_poc 2>/tmp/pd_log; then
	/tmp/pedersen_poc > /tmp/pd_c.txt || { echo "    PEDERSEN POC FAILED"; grep -vE '^REF (commit|share)_' /tmp/pd_c.txt; exit 1; }
	grep -vE '^REF (commit|share)_[0-9]' /tmp/pd_c.txt
	( cd "$HERE" && python3 pedersen_reference.py ) > /tmp/pd_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/pd_c.txt > /tmp/pd_c_ref.txt; grep '^REF' /tmp/pd_py.txt > /tmp/pd_py_ref.txt
	if diff -q /tmp/pd_c_ref.txt /tmp/pd_py_ref.txt >/dev/null; then
		echo "    MATCH: Pedersen VSS C == independent python over $(wc -l < /tmp/pd_c_ref.txt) REF lines"
	else echo "    MISMATCH"; diff /tmp/pd_c_ref.txt /tmp/pd_py_ref.txt | head -4; exit 1; fi
	for k in all_shares_verify tampered_f_rejected tampered_b_rejected reconstruct_t below_threshold_wrong; do
		grep -q "^REF $k YES$" /tmp/pd_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    perfectly-hiding commitments verify shares, reject tampered f or b; t reconstructs"
	rm -rf "$HERE/__pycache__"
else skip_step " no compiler (see /tmp/pd_log)"; fi

echo "[33] RSW time-lock puzzle (create-fast delay, complements Sloth) — C bignum vs independent python"
# Delay functions row (IDEAS-BACKLOG): RSW (Rivest-Shamir-Wagner 1996) -- opening is T sequential
# squarings x^(2^T) mod N (unparallelizable); the factor-knowing owner has a trapdoor e=2^T mod phi(N)
# (two modexps) to rewrap instantly, then discards p,q. No standard KAT; proof = byte-identical C vs
# python + trapdoor==sequential identity + wrong-trapdoor divergence. See docs/DELAY-SPEC.md
RW_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then RW_CC="$c"; break; fi; done
if "$RW_CC" -O2 -Wall -I"$HERE" "$HERE/rsw_poc.c" -o /tmp/rsw_poc 2>/tmp/rw_log; then
	/tmp/rsw_poc > /tmp/rw_c.txt || { echo "    RSW POC FAILED"; cat /tmp/rw_c.txt; exit 1; }
	cat /tmp/rw_c.txt
	( cd "$HERE" && python3 rsw_reference.py ) > /tmp/rw_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/rw_c.txt > /tmp/rw_c_ref.txt; grep '^REF' /tmp/rw_py.txt > /tmp/rw_py_ref.txt
	if diff -q /tmp/rw_c_ref.txt /tmp/rw_py_ref.txt >/dev/null; then
		echo "    MATCH: RSW C (256-bit bignum) == independent python over $(wc -l < /tmp/rw_c_ref.txt) REF lines"
	else echo "    MISMATCH"; diff /tmp/rw_c_ref.txt /tmp/rw_py_ref.txt | head -4; exit 1; fi
	for k in trapdoor_matches_sequential deterministic steps_matter wrong_trapdoor_detected; do
		grep -q "^REF $k YES$" /tmp/rw_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    trapdoor equals the sequential result; wrong factorization diverges"
	rm -rf "$HERE/__pycache__"
else skip_step " no compiler (see /tmp/rw_log)"; fi

echo "[34] scrypt KDF (RFC 7914) — official KATs + hashlib vs C over the in-tree PBKDF2/SHA-256"
# Memory-hard KDF row (IDEAS-BACKLOG): scrypt (Percival, RFC 7914) -- Salsa20/8 -> BlockMix -> ROMix ->
# PBKDF2 wrapper -- a second independent memory-hard KDF alongside Argon2id [11] and Balloon [16]. The
# PBKDF2-HMAC-SHA256 wrapper runs over the REAL in-tree Sha2.c; proven against the RFC 7914 Sec 12 KATs
# and byte-identical to scrypt_reference.py (which also cross-checks CPython hashlib.scrypt). BALLOON-SPEC.
SC_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SC_CC="$c"; break; fi; done
SC_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
SC_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
SC_INC="$INC -I$SRCROOT/Crypto"
if "$SC_CC" -O2 $SC_WNO $SC_NOASM $SC_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/sc_sha2.o 2>/tmp/sc_log \
   && "$SC_CC" -O2 $SC_WNO $SC_NOASM $SC_INC "$HERE/scrypt_poc.c" /tmp/sc_sha2.o -o /tmp/scrypt_poc 2>>/tmp/sc_log; then
	/tmp/scrypt_poc > /tmp/sc_c.txt || { echo "    SCRYPT POC FAILED"; cat /tmp/sc_c.txt; exit 1; }
	grep -E '^REF (rfc_kat|hashlib)' /tmp/sc_c.txt
	( cd "$HERE" && python3 scrypt_reference.py ) > /tmp/sc_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/sc_c.txt > /tmp/sc_c_ref.txt; grep '^REF' /tmp/sc_py.txt > /tmp/sc_py_ref.txt
	if diff -q /tmp/sc_c_ref.txt /tmp/sc_py_ref.txt >/dev/null; then
		echo "    MATCH: scrypt C (in-tree PBKDF2/SHA-256) == python == RFC 7914 KATs == hashlib.scrypt"
	else echo "    MISMATCH"; diff /tmp/sc_c_ref.txt /tmp/sc_py_ref.txt | head -4; exit 1; fi
	grep -q '^REF rfc_kat_match YES$' /tmp/sc_c.txt || { echo "    RFC KAT FAILED"; exit 1; }
	rm -rf "$HERE/__pycache__"
else skip_step " no compiler accepted the stock Crypto sources (see /tmp/sc_log)"; fi

echo "[35] Threshold OPRF (t-of-n password hardening) — real in-tree Sha2 vs independent python"
# Password-protocols row (IDEAS-BACKLOG): threshold OPRF splits the single-server OPRF (step [17]) key
# across n servers via Shamir; any t partial evaluations combine by Lagrange-in-the-exponent to the same
# output, t-1 learn nothing, no server sees the password. Links the REAL in-tree Sha2.c; toprf_reference.py
# is independent. See docs/OPRF-SPEC.md.
TO_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then TO_CC="$c"; break; fi; done
TO_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
TO_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
TO_INC="$INC -I$SRCROOT/Crypto"
if "$TO_CC" -O2 $TO_WNO $TO_NOASM $TO_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/to_sha2.o 2>/tmp/to_log \
   && "$TO_CC" -O2 $TO_WNO $TO_NOASM $TO_INC "$HERE/toprf_poc.c" /tmp/to_sha2.o -o /tmp/toprf_poc 2>>/tmp/to_log; then
	/tmp/toprf_poc > /tmp/to_c.txt || { echo "    TOPRF POC FAILED"; cat /tmp/to_c.txt; exit 1; }
	grep -vE '^REF (threshold_A|single_output|threshold_output)' /tmp/to_c.txt
	( cd "$HERE" && python3 toprf_reference.py ) > /tmp/to_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/to_c.txt > /tmp/to_c_ref.txt; grep '^REF' /tmp/to_py.txt > /tmp/to_py_ref.txt
	if diff -q /tmp/to_c_ref.txt /tmp/to_py_ref.txt >/dev/null; then
		echo "    MATCH: threshold OPRF (real Sha2) == independent python over $(wc -l < /tmp/to_c_ref.txt) REF lines"
	else echo "    MISMATCH"; diff /tmp/to_c_ref.txt /tmp/to_py_ref.txt | head -4; exit 1; fi
	for k in threshold_matches_single any_t_subset_agrees below_threshold_differs server_sees_only_blinded; do
		grep -q "^REF $k YES$" /tmp/to_c.txt || { echo "    PROPERTY $k FAILED"; exit 1; }
	done
	echo "    any t servers reconstruct the single-key output; t-1 differ; servers see only the blind"
	rm -rf "$HERE/__pycache__"
else skip_step " no compiler accepted the stock Crypto sources (see /tmp/to_log)"; fi

echo "[36] AF-split keyslot records ([FORMAT] integration): real AfSplit.c + KeyslotStore.c vs independent python"
# docs/AF-SPLIT-SPEC.md integration: the wrapped payload is AF-split into s stripes before wrapping, so
# a partial remnant of a slot yields nothing. Labeled v2 records carry s (authenticated); bare records
# stay field-free; s is public config like cost, so the constant-time search's work stays fixed.
# Links the REAL in-tree modules; keyslotaf_reference.py is independent (hashlib + reimplemented
# ChaCha20 + spec-reimplemented AF diffuse incl. the trailing partial section).
KA_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KA_CC="$c"; break; fi; done
KA_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
KA_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KA_GC="-ffunction-sections -fdata-sections"
KA_INC="$INC -I$SRCROOT/Crypto"
if "$KA_CC" -O2 $KA_WNO $KA_NOASM $KA_GC -DVC_ENABLE_KEYSLOTS $KA_INC -c "$SRCROOT/Common/AfSplit.c"      -o /tmp/ka_afsplit.o 2>/tmp/ka_cc.log \
   && "$KA_CC" -O2 $KA_WNO $KA_NOASM $KA_GC -DVC_ENABLE_KEYSLOTS $KA_INC -c "$SRCROOT/Common/Keyslot.c"      -o /tmp/ka_keyslot.o 2>>/tmp/ka_cc.log \
   && "$KA_CC" -O2 $KA_WNO $KA_NOASM $KA_GC -DVC_ENABLE_KEYSLOTS $KA_INC -c "$SRCROOT/Common/KeyslotStore.c" -o /tmp/ka_store.o 2>>/tmp/ka_cc.log \
   && "$KA_CC" -O2 $KA_WNO $KA_NOASM $KA_GC $KA_INC -c "$SRCROOT/Crypto/Sha2.c"      -o /tmp/ka_sha2.o   2>>/tmp/ka_cc.log \
   && "$KA_CC" -O2 $KA_WNO $KA_NOASM $KA_GC $KA_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ka_chacha.o 2>>/tmp/ka_cc.log \
   && "$KA_CC" -O2 $KA_WNO $KA_NOASM -DVC_ENABLE_KEYSLOTS $KA_INC "$HERE/keyslotaf_test.c" \
        /tmp/ka_afsplit.o /tmp/ka_keyslot.o /tmp/ka_store.o /tmp/ka_sha2.o /tmp/ka_chacha.o -Wl,--gc-sections -o /tmp/keyslotaf_test 2>>/tmp/ka_cc.log; then
	if /tmp/keyslotaf_test > /tmp/ka_c.txt; then grep -vE '^REF af (labeled|bare) record' /tmp/ka_c.txt
	else cat /tmp/ka_c.txt; echo "    AF KEYSLOT TEST FAILED"; exit 1; fi
	( cd "$HERE" && python3 keyslotaf_reference.py ) > /tmp/ka_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/ka_c.txt > /tmp/ka_c_ref.txt
	if diff -q /tmp/ka_c_ref.txt /tmp/ka_py.txt >/dev/null; then
		echo "    MATCH: AF keyslot records (real compiled modules) == independent python over $(wc -l < /tmp/ka_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/ka_c_ref.txt /tmp/ka_py.txt | head -4; exit 1
	fi
	if grep -Eq '= NO$' /tmp/ka_c.txt; then echo "    AF PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ka_cc.log)"
fi

echo "[37] KeyslotArea volume-I/O bindings: real KeyslotAreaFile.c over synthetic containers (KEYSLOTS-SPEC §9)"
# The volume-I/O seam from docs/KEYSLOTS-SPEC.md §9, file-backed: KSB_HEADER binds the primary
# header's reserved slack [512, 64K) (real header/hidden-header/data byte-untouched, slots survive a
# cold reopen), KSB_SIDECAR the whole file, KSB_DENIABLE a free extent clamped below a hidden-volume
# start (snapshot diff confined to one stride slot; slot blends into random fill; the location leak
# under multi-snapshot is asserted AS the documented limitation). Behavioural I/O test like step [9]
# (the record crypto is proven in [8]/[36]).
KB_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KB_CC="$c"; break; fi; done
KB_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
KB_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KB_GC="-ffunction-sections -fdata-sections"
KB_INC="$INC -I$SRCROOT/Crypto"
if "$KB_CC" -O2 $KB_WNO $KB_NOASM $KB_GC -DVC_ENABLE_KEYSLOTS $KB_INC -c "$SRCROOT/Common/KeyslotAreaFile.c" -o /tmp/kb_areafile.o 2>/tmp/kb_cc.log \
   && "$KB_CC" -O2 $KB_WNO $KB_NOASM $KB_GC -DVC_ENABLE_KEYSLOTS $KB_INC -c "$SRCROOT/Common/AfSplit.c"      -o /tmp/kb_afsplit.o 2>>/tmp/kb_cc.log \
   && "$KB_CC" -O2 $KB_WNO $KB_NOASM $KB_GC -DVC_ENABLE_KEYSLOTS $KB_INC -c "$SRCROOT/Common/Keyslot.c"      -o /tmp/kb_keyslot.o 2>>/tmp/kb_cc.log \
   && "$KB_CC" -O2 $KB_WNO $KB_NOASM $KB_GC -DVC_ENABLE_KEYSLOTS $KB_INC -c "$SRCROOT/Common/KeyslotStore.c" -o /tmp/kb_store.o 2>>/tmp/kb_cc.log \
   && "$KB_CC" -O2 $KB_WNO $KB_NOASM $KB_GC $KB_INC -c "$SRCROOT/Crypto/Sha2.c"      -o /tmp/kb_sha2.o   2>>/tmp/kb_cc.log \
   && "$KB_CC" -O2 $KB_WNO $KB_NOASM $KB_GC $KB_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/kb_chacha.o 2>>/tmp/kb_cc.log \
   && "$KB_CC" -O2 $KB_WNO $KB_NOASM -DVC_ENABLE_KEYSLOTS $KB_INC "$HERE/keyslotarea_test.c" \
        /tmp/kb_areafile.o /tmp/kb_afsplit.o /tmp/kb_keyslot.o /tmp/kb_store.o /tmp/kb_sha2.o /tmp/kb_chacha.o -Wl,--gc-sections -o /tmp/keyslotarea_test 2>>/tmp/kb_cc.log; then
	if /tmp/keyslotarea_test > /tmp/kb_out.txt; then cat /tmp/kb_out.txt
	else cat /tmp/kb_out.txt; echo "    KEYSLOT AREA TEST FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/kb_cc.log)"
fi

echo "[38] Balloon as a mountable PRF: real Common/Pkcs5.c derive_key_balloon vs independent python"
# docs/BALLOON-SPEC.md integration: the step-[16]-proven Balloon core becomes the shipping
# derive_key_balloon (VC_ENABLE_BALLOON_KDF: PRF id, Volumes.c/thread-pool dispatch, Pkcs5Balloon
# C++ class). Compiles the REAL Pkcs5.c TU (step [11]'s pattern) + real Sha2/Argon2 objects; the
# python reference chains itself to the [16] anchor (asserts 635ebeac...) before emitting vectors.
# REF-diffs dk32/dk64/dk192 (incl. the counter expansion) + the PIM->(t,space) resolver + override;
# also checks abort fail-closed and benchmarks vs the real Argon2id (informational).
BF_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then BF_CC="$c"; break; fi; done
BF_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
BF_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
BF_GC="-ffunction-sections -fdata-sections"
BF_INC="$INC -I$SRCROOT/Crypto -I$SRCROOT/Crypto/Argon2/include -I$SRCROOT/Crypto/Argon2/src"
BF_ARG="$SRCROOT/Crypto/Argon2/src"
printf 'volatile int g_hasSSE2=1,g_hasAVX2=0,g_hasSSE42=0,g_hasAVX=0,g_hasSSSE3=0,g_hasAESNI=0,g_hasSHA256=0,g_isIntel=0,g_isAMD=0,g_hasSSE41=0,g_hasRDRAND=0,g_hasRDSEED=0;\n' > /tmp/bf_stub.c
if "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS $BF_INC -c "$BF_ARG/argon2.c" -o /tmp/bf_argon2.o 2>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS $BF_INC -c "$BF_ARG/core.c"   -o /tmp/bf_core.o   2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS $BF_INC -c "$BF_ARG/ref.c"    -o /tmp/bf_ref.o    2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS $BF_INC -c "$BF_ARG/blake2/blake2b.c" -o /tmp/bf_b2.o 2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS -msse2 $BF_INC -c "$BF_ARG/opt_sse2.c" -o /tmp/bf_sse2.o 2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS -mavx2 -msse2 $BF_INC -c "$BF_ARG/opt_avx2.c" -o /tmp/bf_avx2.o 2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_NOASM $BF_GC $BF_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/bf_sha2.o 2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO $BF_GC -DARGON2_NO_THREADS -DVC_ENABLE_ARGON2_PARAMS -DVC_ENABLE_BALLOON_KDF $BF_INC -c "$SRCROOT/Common/Pkcs5.c" -o /tmp/bf_pkcs5.o 2>>/tmp/bf_log \
   && "$BF_CC" -O2 $BF_WNO -DARGON2_NO_THREADS -DVC_ENABLE_ARGON2_PARAMS -DVC_ENABLE_BALLOON_KDF $BF_INC "$HERE/balloon_prf_test.c" /tmp/bf_stub.c \
        /tmp/bf_pkcs5.o /tmp/bf_sha2.o /tmp/bf_argon2.o /tmp/bf_core.o /tmp/bf_ref.o /tmp/bf_b2.o /tmp/bf_sse2.o /tmp/bf_avx2.o \
        -Wl,--gc-sections -o /tmp/balloon_prf_test 2>>/tmp/bf_log; then
	/tmp/balloon_prf_test > /tmp/bf_c.txt || { echo "    BALLOON PRF TEST FAILED"; cat /tmp/bf_c.txt; exit 1; }
	grep -vE '^REF balloon dk' /tmp/bf_c.txt
	( cd "$HERE" && python3 balloon_prf_reference.py ) > /tmp/bf_py.txt || { echo "    PYTHON REFERENCE FAILED (incl. step-[16] anchor chain)"; exit 1; }
	grep '^REF' /tmp/bf_c.txt > /tmp/bf_c_ref.txt
	if diff -q /tmp/bf_c_ref.txt /tmp/bf_py.txt >/dev/null; then
		echo "    MATCH: shipping derive_key_balloon (real Pkcs5.c object) == independent python over $(wc -l < /tmp/bf_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/bf_c_ref.txt /tmp/bf_py.txt | head -4; exit 1
	fi
	if grep -Eq '= NO$' /tmp/bf_c.txt; then echo "    BALLOON PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Pkcs5/Argon2 sources (see /tmp/bf_log)"
fi

echo "[39] Network share at PRODUCTION parameters: McCallum-Relyea over full Ed25519 vs independent python"
# docs/NETWORK-SHARE-SPEC.md "Shipping parameters": the spec mandates a FULL-GROUP curve (P-256 or
# Ed25519) because MR needs point ADDITION X = C + e*G, not an x-only ladder. This replaces step
# [10]'s 61-bit toy field with the real Ed25519 group, implemented from scratch (extended
# coordinates, single final inversion) on the proven 256-bit bignum core. Proven two ways: (1) an
# OFFICIAL KAT -- the three RFC 8032 section 7.1 Ed25519 public keys anchor the group to the
# standard; (2) the MR values + share diffed byte-for-byte vs netshare_ed25519_reference.py.
# Links the REAL in-tree Sha2.c (SHA-512 clamp + SHA-256 share). Transport + CLI stay real-build.
NE_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then NE_CC="$c"; break; fi; done
NE_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
NE_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
NE_GC="-ffunction-sections -fdata-sections"
NE_INC="$INC -I$SRCROOT/Crypto"
if "$NE_CC" -O2 $NE_WNO $NE_NOASM $NE_GC $NE_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/ne_sha2.o 2>/tmp/ne_cc.log \
   && "$NE_CC" -O2 $NE_WNO $NE_NOASM $NE_INC "$HERE/netshare_ed25519_poc.c" /tmp/ne_sha2.o -Wl,--gc-sections -o /tmp/netshare_ed25519_poc 2>>/tmp/ne_cc.log; then
	/tmp/netshare_ed25519_poc > /tmp/ne_c.txt || { echo "    NETSHARE ED25519 POC FAILED"; cat /tmp/ne_c.txt; exit 1; }
	grep -vE '^REF (rfc8032|mr Kprov)' /tmp/ne_c.txt
	python3 "$HERE/netshare_ed25519_reference.py" > /tmp/ne_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/ne_c.txt > /tmp/ne_c_ref.txt; grep '^REF' /tmp/ne_py.txt > /tmp/ne_py_ref.txt
	if diff -q /tmp/ne_c_ref.txt /tmp/ne_py_ref.txt >/dev/null; then
		echo "    MATCH: MR over Ed25519 (real Sha2 + from-scratch group) == independent python over $(wc -l < /tmp/ne_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/ne_c_ref.txt /tmp/ne_py_ref.txt | head -6; exit 1
	fi
	# the first three REF lines must equal the official RFC 8032 section 7.1 public keys
	RFC1=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
	RFC2=3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
	RFC3=fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
	if [ "$(grep 'rfc8032 pub' /tmp/ne_c.txt | sed -n 1p | sed 's/.*= //')" = "$RFC1" ] \
	   && [ "$(grep 'rfc8032 pub' /tmp/ne_c.txt | sed -n 2p | sed 's/.*= //')" = "$RFC2" ] \
	   && [ "$(grep 'rfc8032 pub' /tmp/ne_c.txt | sed -n 3p | sed 's/.*= //')" = "$RFC3" ]; then
		echo "    KAT: Ed25519 group reproduces the official RFC 8032 7.1 public keys"
	else
		echo "    RFC 8032 KAT MISMATCH"; exit 1
	fi
	if grep -Eq '= NO$' /tmp/ne_c.txt; then echo "    MR PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ne_cc.log)"
fi

echo "[40] Keyed per-share MAC: real Common/Shamir.c + ShamirMac.c vs independent python"
# docs/VSS-SPEC.md / IDEAS-BACKLOG D: plain Shamir + the CRC-32 checksum catch ACCIDENTAL corruption;
# a keyed MAC is what catches an ADVERSARIAL one. Each GF(2^8) share is tagged
# HMAC-SHA256(macKey, "VCSMshare1" || x || len || y[]) so a flipped/truncated/relabelled/fabricated
# share is rejected before shamir_combine. Links the REAL Shamir.c + ShamirMac.c + Sha2.c;
# shamir_mac_reference.py is independent (stdlib hmac + reimplemented GF(2^8) split). NOTE: this is
# the adversarial-SHARE half; dealer-consistency VSS stays the prime-field scheme (steps [31]/[32]).
SM_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SM_CC="$c"; break; fi; done
SM_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
SM_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
SM_GC="-ffunction-sections -fdata-sections"
SM_INC="$INC -I$SRCROOT/Crypto"
if "$SM_CC" -O2 $SM_WNO $SM_NOASM $SM_GC -DVC_ENABLE_SHAMIR_MAC $SM_INC -c "$SRCROOT/Common/Shamir.c"    -o /tmp/sm_shamir.o 2>/tmp/sm_cc.log \
   && "$SM_CC" -O2 $SM_WNO $SM_NOASM $SM_GC -DVC_ENABLE_SHAMIR_MAC $SM_INC -c "$SRCROOT/Common/ShamirMac.c" -o /tmp/sm_mac.o 2>>/tmp/sm_cc.log \
   && "$SM_CC" -O2 $SM_WNO $SM_NOASM $SM_GC $SM_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/sm_sha2.o 2>>/tmp/sm_cc.log \
   && "$SM_CC" -O2 $SM_WNO $SM_NOASM -DVC_ENABLE_SHAMIR_MAC $SM_INC "$HERE/shamir_mac_test.c" \
        /tmp/sm_shamir.o /tmp/sm_mac.o /tmp/sm_sha2.o -Wl,--gc-sections -o /tmp/shamir_mac_test 2>>/tmp/sm_cc.log; then
	if /tmp/shamir_mac_test > /tmp/sm_c.txt; then cat /tmp/sm_c.txt
	else cat /tmp/sm_c.txt; echo "    SHAMIR MAC TEST FAILED"; exit 1; fi
	( cd "$HERE" && python3 shamir_mac_reference.py ) > /tmp/sm_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/sm_c.txt > /tmp/sm_c_ref.txt
	if diff -q /tmp/sm_c_ref.txt /tmp/sm_py.txt >/dev/null; then
		echo "    MATCH: keyed per-share MAC (real Shamir/Sha2 objects) == independent python over $(wc -l < /tmp/sm_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/sm_c_ref.txt /tmp/sm_py.txt | head -4; exit 1
	fi
	if grep -Eq 'FAIL$' /tmp/sm_c.txt; then echo "    SHAMIR MAC PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/sm_cc.log)"
fi

echo "[41] Shamir GF(2^8) timing-leakage screen (dudect): real gf_mul/gf_inv are constant-time"
# ROADMAP item 15 follow-up (lines ~89-90): Shamir.c's gf_mul/gf_inv were rewritten branchless +
# table-free to remove a cache/branch side channel; this MEASURES that with a dudect-style
# (Reparaz-Balasch-Yarom) Welch t-test. Statistical, not a byte KAT, so it is SELF-VALIDATING: the
# same screen runs on the real branchless gf_mul/gf_inv AND a deliberately variable-time leaky mul,
# and must FLAG the leaky one while CLEARING the real ones -- that contrast is stable across machines.
DU_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then DU_CC="$c"; break; fi; done
if "$DU_CC" -O2 -I"$SRCROOT" -I"$SRCROOT/Common" "$HERE/shamir_dudect_test.c" -lm -o /tmp/shamir_dudect 2>/tmp/du_log; then
	if /tmp/shamir_dudect > /tmp/du_out.txt; then cat /tmp/du_out.txt
	else cat /tmp/du_out.txt; echo "    SHAMIR DUDECT SCREEN FAILED"; exit 1; fi
	grep -q '^gf_mul vs leaky table agree on all 65536 products = YES$' /tmp/du_out.txt || { echo "    LEAKY REF COMPUTES WRONG PRODUCT"; exit 1; }
else
	skip_step " no compiler built the dudect harness (see /tmp/du_log)"
fi

echo "[42] Transcribable share encoding (bech32/BIP-173): real ShareCode.c + Shamir.c vs independent python"
# docs/VSS-SPEC.md / IDEAS-BACKLOG D "SLIP-39-style encoding": a typo-detecting text form for a
# recovery share. Uses a bech32 (BIP-173) BCH checksum (<=4 substitution errors detected while the
# string is <=90 chars) over ver||x||len||y[||mac]. Links the REAL ShareCode.c + Shamir.c;
# sharecode_reference.py is independent (spec bech32 + reimplemented GF(2^8) split). Anchored to the
# official BIP-173 vector (bech32("a",empty)==a12uel5l); every single-char typo in a sample rejected.
SR_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SR_CC="$c"; break; fi; done
SR_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
SR_INC="$INC -I$SRCROOT/Crypto"
if "$SR_CC" -O2 $SR_WNO -DVC_ENABLE_SHARECODE $SR_INC -c "$SRCROOT/Common/ShareCode.c" -o /tmp/sr_sharecode.o 2>/tmp/sr_log \
   && "$SR_CC" -O2 $SR_WNO $SR_INC -c "$SRCROOT/Common/Shamir.c" -o /tmp/sr_shamir.o 2>>/tmp/sr_log \
   && "$SR_CC" -O2 $SR_WNO -DVC_ENABLE_SHARECODE $SR_INC "$HERE/sharecode_test.c" /tmp/sr_sharecode.o /tmp/sr_shamir.o -o /tmp/sharecode_test 2>>/tmp/sr_log; then
	if /tmp/sharecode_test > /tmp/sr_c.txt; then cat /tmp/sr_c.txt
	else cat /tmp/sr_c.txt; echo "    SHARECODE TEST FAILED"; exit 1; fi
	( cd "$HERE" && python3 sharecode_reference.py ) > /tmp/sr_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/sr_c.txt > /tmp/sr_c_ref.txt
	if diff -q /tmp/sr_c_ref.txt /tmp/sr_py.txt >/dev/null; then
		echo "    MATCH: bech32 share codes (real ShareCode/Shamir objects) == independent python over $(wc -l < /tmp/sr_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/sr_c_ref.txt /tmp/sr_py.txt | head -4; exit 1
	fi
	if grep -Eq 'FAIL$' /tmp/sr_c.txt; then echo "    SHARECODE PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock sources (see /tmp/sr_log)"
fi

echo "[43] OPRF at PRODUCTION parameters: DH-OPRF over full ristretto255 (RFC 9497) vs independent python"
# docs/OPRF-SPEC.md: step [17]'s OPRF used a 61-bit toy field; this is the real CFRG ciphersuite group
# OPRF(ristretto255, SHA-512). From-scratch ristretto255 (RFC 9496 encode + Elligator2) +
# expand_message_xmd(SHA-512) (RFC 9380) on the step-[39] field, over the REAL in-tree Sha2.c. Proven
# three ways: (1) OFFICIAL KAT -- ristretto encodings of 1B..5B == RFC 9496 A.1; (2) OPRF
# Blind/Evaluate/Finalize diffed byte-for-byte vs oprf_ristretto_reference.py; (3) identity /
# blind-independence / wrong-key-differs properties. Transport + RFC 9497 e2e vectors stay real-build.
OR_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then OR_CC="$c"; break; fi; done
OR_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
OR_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
OR_GC="-ffunction-sections -fdata-sections"
OR_INC="$INC -I$SRCROOT/Crypto"
if "$OR_CC" -O2 $OR_WNO $OR_NOASM $OR_GC $OR_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/or_sha2.o 2>/tmp/or_cc.log \
   && "$OR_CC" -O2 $OR_WNO $OR_NOASM $OR_INC "$HERE/oprf_ristretto_poc.c" /tmp/or_sha2.o -Wl,--gc-sections -o /tmp/oprf_ristretto_poc 2>>/tmp/or_cc.log; then
	/tmp/oprf_ristretto_poc > /tmp/or_c.txt || { echo "    OPRF RISTRETTO POC FAILED (basepoint KAT)"; cat /tmp/or_c.txt; exit 1; }
	grep -vE '^REF ristretto' /tmp/or_c.txt
	python3 "$HERE/oprf_ristretto_reference.py" > /tmp/or_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/or_c.txt > /tmp/or_c_ref.txt; grep '^REF' /tmp/or_py.txt > /tmp/or_py_ref.txt
	if diff -q /tmp/or_c_ref.txt /tmp/or_py_ref.txt >/dev/null; then
		echo "    MATCH: ristretto255 OPRF (real Sha2 + from-scratch group) == independent python over $(wc -l < /tmp/or_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/or_c_ref.txt /tmp/or_py_ref.txt | head -6; exit 1
	fi
	grep -q '^ristretto255 basepoint KAT (RFC 9496) = YES$' /tmp/or_c.txt || { echo "    RFC 9496 KAT FAILED"; exit 1; }
	if grep -Eq '= NO$' /tmp/or_c.txt; then echo "    OPRF PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/or_cc.log)"
fi

echo "[44] Threshold OPRF over ristretto255 (PPSS): real Sha2 + from-scratch group vs independent python"
# docs/OPRF-SPEC.md "Threshold OPRF / PPSS": step [43]'s ristretto255 OPRF composed with a Shamir split
# of the server key over the scalar field Z_L, so no single server holds k. Each server returns a
# partial k_i*BE; any t combine by Lagrange-in-the-exponent to k*BE (the single-key output), t-1 learn
# nothing. Anchors the group to the RFC 9496 KAT; threshold output diffed byte-for-byte vs python.
TR_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then TR_CC="$c"; break; fi; done
TR_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
TR_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
TR_INC="$INC -I$SRCROOT/Crypto"
if "$TR_CC" -O2 $TR_WNO $TR_NOASM $TR_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/tr_sha2.o 2>/tmp/tr_cc.log \
   && "$TR_CC" -O2 $TR_WNO $TR_NOASM $TR_INC "$HERE/toprf_ristretto_poc.c" /tmp/tr_sha2.o -Wl,--gc-sections -o /tmp/toprf_ristretto_poc 2>>/tmp/tr_cc.log; then
	/tmp/toprf_ristretto_poc > /tmp/tr_c.txt || { echo "    TOPRF RISTRETTO POC FAILED (basepoint KAT)"; cat /tmp/tr_c.txt; exit 1; }
	grep -v '^REF' /tmp/tr_c.txt
	python3 "$HERE/toprf_ristretto_reference.py" > /tmp/tr_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/tr_c.txt > /tmp/tr_c_ref.txt; grep '^REF' /tmp/tr_py.txt > /tmp/tr_py_ref.txt
	if diff -q /tmp/tr_c_ref.txt /tmp/tr_py_ref.txt >/dev/null; then
		echo "    MATCH: threshold OPRF over ristretto255 == independent python over $(wc -l < /tmp/tr_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/tr_c_ref.txt /tmp/tr_py_ref.txt | head -4; exit 1
	fi
	grep -q '^ristretto255 basepoint KAT (RFC 9496) = YES$' /tmp/tr_c.txt || { echo "    RFC 9496 KAT FAILED"; exit 1; }
	if grep -Eq '= NO$' /tmp/tr_c.txt; then echo "    TOPRF PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/tr_cc.log)"
fi

echo "[45] Randomized/differential robustness: real Shamir/ShamirMac/ShareCode/Keyslot over seeded fuzzing"
# IDEAS-BACKLOG "Randomized differential testing": beyond fixed KATs, a seeded fuzzer drives the REAL
# compiled modules over thousands of random + boundary configs (degenerate thresholds t=2/t=n,
# duplicate x-coords, zero/max secret lengths, random keyslot add/open/revoke, ShareCode corruption),
# asserting invariants hold and nothing crashes or silently returns a wrong answer. Seeded => the
# verdict is reproducible. Behavioural (no python diff), like steps [9]/[37].
DF_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then DF_CC="$c"; break; fi; done
DF_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
DF_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
DF_GC="-ffunction-sections -fdata-sections"
DF_DEF="-DVC_ENABLE_SHAMIR_MAC -DVC_ENABLE_SHARECODE -DVC_ENABLE_KEYSLOTS"
DF_INC="$INC -I$SRCROOT/Crypto"
DF_OK=1
for m in Shamir ShamirMac ShareCode Keyslot KeyslotStore AfSplit; do
	"$DF_CC" -O2 $DF_WNO $DF_NOASM $DF_GC $DF_DEF $DF_INC -c "$SRCROOT/Common/$m.c" -o /tmp/df_$m.o 2>>/tmp/df_cc.log || DF_OK=0
done
"$DF_CC" -O2 $DF_WNO $DF_NOASM $DF_GC $DF_INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/df_sha2.o   2>>/tmp/df_cc.log || DF_OK=0
"$DF_CC" -O2 $DF_WNO $DF_NOASM $DF_GC $DF_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/df_chacha.o 2>>/tmp/df_cc.log || DF_OK=0
if [ "$DF_OK" = 1 ] && "$DF_CC" -O2 $DF_WNO $DF_NOASM $DF_DEF $DF_INC "$HERE/differential_test.c" \
     /tmp/df_Shamir.o /tmp/df_ShamirMac.o /tmp/df_ShareCode.o /tmp/df_Keyslot.o /tmp/df_KeyslotStore.o /tmp/df_AfSplit.o /tmp/df_sha2.o /tmp/df_chacha.o \
     -Wl,--gc-sections -o /tmp/differential_test 2>>/tmp/df_cc.log; then
	if /tmp/differential_test > /tmp/df_out.txt; then cat /tmp/df_out.txt
	else cat /tmp/df_out.txt; echo "    DIFFERENTIAL CHECKS FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the stock sources (see /tmp/df_cc.log)"
fi

echo "[46] Keyslot constant-time compare timing screen (dudect): KeyslotConstTimeEqual is data-oblivious"
# IDEAS-BACKLOG "Constant-time verification in CI -- over the Shamir AND keyslot paths": step [41]
# screened the Shamir GF(2^8) primitives; this screens the keyslot MAC-as-slot-selector compare
# (KeyslotConstTimeEqual). Same self-validating dudect Welch t-test: runs on the real compare AND a
# leaky early-out memcmp, must FLAG the leaky one (class 0 differs in byte 0, class 1 in the last
# byte) and CLEAR the constant-time one. Contrast-based => stable across machines.
KE_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KE_CC="$c"; break; fi; done
KE_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
KE_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KE_GC="-ffunction-sections -fdata-sections"
KE_INC="$INC -I$SRCROOT/Crypto"
if "$KE_CC" -O2 $KE_WNO $KE_NOASM $KE_GC -DVC_ENABLE_KEYSLOTS $KE_INC -c "$SRCROOT/Common/Keyslot.c" -o /tmp/ke_keyslot.o 2>/tmp/ke_log \
   && "$KE_CC" -O2 $KE_WNO $KE_NOASM $KE_GC $KE_INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/ke_sha2.o   2>>/tmp/ke_log \
   && "$KE_CC" -O2 $KE_WNO $KE_NOASM $KE_GC $KE_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ke_chacha.o 2>>/tmp/ke_log \
   && "$KE_CC" -O2 $KE_WNO $KE_NOASM -DVC_ENABLE_KEYSLOTS $KE_INC "$HERE/keyslot_dudect_test.c" /tmp/ke_keyslot.o /tmp/ke_sha2.o /tmp/ke_chacha.o -lm -Wl,--gc-sections -o /tmp/keyslot_dudect 2>>/tmp/ke_log; then
	if /tmp/keyslot_dudect > /tmp/ke_out.txt; then cat /tmp/ke_out.txt
	else cat /tmp/ke_out.txt; echo "    KEYSLOT DUDECT SCREEN FAILED"; exit 1; fi
	grep -q '^const-time vs leaky compare agree on all verdicts = YES$' /tmp/ke_out.txt || { echo "    LEAKY REF WRONG VERDICT"; exit 1; }
else
	skip_step " no compiler built the keyslot dudect harness (see /tmp/ke_log)"
fi

echo "[47] Verifiable OPRF (DLEQ proof) over ristretto255: real Sha2 + from-scratch group vs independent python"
# docs/OPRF-SPEC.md verifiable mode: the server commits pk=k*G and proves in zero knowledge (Chaum-
# Pedersen / DLEQ) that the SAME k gave EE=k*BE, so a swapped key or a tampered EE is caught. Reuses
# the step-[43] ristretto255 group over the REAL Sha2.c. Anchors the group to the RFC 9496 KAT;
# the proof (c,s)+pk (fixed nonce, deterministic) diffed byte-for-byte vs python; valid verifies,
# tampered EE and wrong committed key rejected.
VO_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then VO_CC="$c"; break; fi; done
VO_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
VO_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
VO_INC="$INC -I$SRCROOT/Crypto"
if "$VO_CC" -O2 $VO_WNO $VO_NOASM $VO_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/vo_sha2.o 2>/tmp/vo_cc.log \
   && "$VO_CC" -O2 $VO_WNO $VO_NOASM $VO_INC "$HERE/voprf_ristretto_poc.c" /tmp/vo_sha2.o -Wl,--gc-sections -o /tmp/voprf_ristretto_poc 2>>/tmp/vo_cc.log; then
	/tmp/voprf_ristretto_poc > /tmp/vo_c.txt || { echo "    VOPRF POC FAILED (basepoint KAT)"; cat /tmp/vo_c.txt; exit 1; }
	grep -v '^REF' /tmp/vo_c.txt
	python3 "$HERE/voprf_ristretto_reference.py" > /tmp/vo_py.txt || { echo "    PYTHON REFERENCE FAILED"; exit 1; }
	grep '^REF' /tmp/vo_c.txt > /tmp/vo_c_ref.txt; grep '^REF' /tmp/vo_py.txt > /tmp/vo_py_ref.txt
	if diff -q /tmp/vo_c_ref.txt /tmp/vo_py_ref.txt >/dev/null; then
		echo "    MATCH: VOPRF DLEQ over ristretto255 == independent python over $(wc -l < /tmp/vo_c_ref.txt) REF lines"
	else
		echo "    MISMATCH"; diff /tmp/vo_c_ref.txt /tmp/vo_py_ref.txt | head -4; exit 1
	fi
	grep -q '^ristretto255 basepoint KAT (RFC 9496) = YES$' /tmp/vo_c.txt || { echo "    RFC 9496 KAT FAILED"; exit 1; }
	if grep -Eq '= NO$' /tmp/vo_c.txt; then echo "    VOPRF PROPERTY FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/vo_cc.log)"
fi

echo "[48] Catena-BRG memory-hard KDF core (survey alongside Balloon/scrypt) vs independent python"
# IDEAS-BACKLOG "memory-hard alternatives to benchmark against Argon2id": the bit-reversal-graph (BRG)
# memory-hard core in the Catena style (Forler-Lucks-Wenzel) over the REAL in-tree SHA-256 -- a
# sequential fill of 2^g blocks then lambda BRG passes whose bit-reversal permutation forces
# whole-array access. Memory-hard CORE, not the full keyed Catena KDF. catena_reference.py is
# independent (hashlib).
CA_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then CA_CC="$c"; break; fi; done
CA_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
CA_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
CA_GC="-ffunction-sections -fdata-sections"
CA_INC="$INC -I$SRCROOT/Crypto"
if "$CA_CC" -O2 $CA_WNO $CA_NOASM $CA_GC $CA_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/ca_sha2.o 2>/tmp/ca_log \
   && "$CA_CC" -O2 $CA_WNO $CA_NOASM $CA_INC "$HERE/catena_poc.c" /tmp/ca_sha2.o -Wl,--gc-sections -o /tmp/catena_poc 2>>/tmp/ca_log; then
	/tmp/catena_poc > /tmp/ca_c.txt; grep -v '^REF' /tmp/ca_c.txt
	python3 "$HERE/catena_reference.py" > /tmp/ca_py.txt
	grep '^REF' /tmp/ca_c.txt > /tmp/ca_c_ref.txt; grep '^REF' /tmp/ca_py.txt > /tmp/ca_py_ref.txt
	if diff -q /tmp/ca_c_ref.txt /tmp/ca_py_ref.txt >/dev/null; then
		echo "    MATCH: Catena-BRG core (real Sha2 object) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/ca_c_ref.txt /tmp/ca_py_ref.txt; exit 1
	fi
	if grep -Eq '= NO$' /tmp/ca_c.txt; then echo "    CATENA POC FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/ca_log)"
fi

echo ""
echo "[49] Network-bound share END TO END over a real transport: McCallum-Relyea client <-> forked server"
# Closes docs/NETWORK-SHARE-SPEC.md "What remains to build" as far as a sandbox can: the exchange proven
# at Ed25519 production parameters (step 39) is now driven through an ACTUAL kernel AF_UNIX socket to a
# separate server process, with a stored C-blob. Self-validating (enroll share == socket-recovered
# share; blinded X hides C; off-network fails; wrong server fails) + the enrolled share is diffed
# byte-for-byte against an independent python (netshare_transport_reference.py). Real in-tree Sha2.c.
NT_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then NT_CC="$c"; break; fi; done
NT_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
NT_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
NT_GC="-ffunction-sections -fdata-sections"
NT_INC="$INC -I$SRCROOT/Crypto"
if "$NT_CC" -O2 $NT_WNO $NT_NOASM $NT_GC $NT_INC -c "$SRCROOT/Crypto/Sha2.c" -o /tmp/nt_sha2.o 2>/tmp/nt_log \
   && "$NT_CC" -O2 $NT_WNO $NT_NOASM $NT_INC "$HERE/netshare_transport_poc.c" /tmp/nt_sha2.o -Wl,--gc-sections -o /tmp/netshare_transport_poc 2>>/tmp/nt_log; then
	/tmp/netshare_transport_poc > /tmp/nt_c.txt; cat /tmp/nt_c.txt
	python3 "$HERE/netshare_transport_reference.py" > /tmp/nt_py.txt
	c_share="$(grep -oE 'enrolled share \(c\*S\)[ ]*= [0-9a-f]+' /tmp/nt_c.txt | grep -oE '[0-9a-f]{64}')"
	p_share="$(grep -oE 'REF enrolled share = [0-9a-f]+' /tmp/nt_py.txt | grep -oE '[0-9a-f]{64}')"
	if [ -n "$c_share" ] && [ "$c_share" = "$p_share" ]; then
		echo "    MATCH: enrolled MR share (real Sha2, Ed25519) == independent python reference"
	else
		echo "    MISMATCH (c=$c_share py=$p_share)"; exit 1
	fi
	if ! grep -q '^NETSHARE TRANSPORT ROUND-TRIP PASSED' /tmp/nt_c.txt; then echo "    NETSHARE TRANSPORT FAILED"; exit 1; fi
	rm -rf "$HERE/__pycache__"
else
	skip_step " no compiler accepted the stock Crypto sources (see /tmp/nt_log)"
fi

echo ""
echo "[50] Guard-complementarity lint: multiply-defined external symbols have disjoint #if guards"
# ROI item 12. Pure static analysis (python only, never skips). Enforces mechanically what a comment
# once merely claimed: a symbol defined in two .c files under feature guards must have COMPLEMENTARY
# guards, or some flag combination link-collides (the HKFScrubActiveConfig class). The --self-test is
# the negative control: it re-injects the historical broken guard and asserts the lint flags it while
# the real tree stays clean.
if python3 "$HERE/guard_lint.py"; then
	if python3 "$HERE/guard_lint.py" --self-test; then
		echo "    MATCH: guard-complementarity holds tree-wide; lint proven to flag a reintroduced collision"
	else
		echo "    GUARD-LINT SELF-TEST FAILED (the lint no longer detects a known collision)"; exit 1
	fi
else
	echo "    GUARD-LINT FAILED: a multiply-defined external symbol has overlapping guards"; exit 1
fi

echo ""
echo "[51] Link-time symbol-collision check: KEYSCRUB x HKF combos link with no duplicate symbol"
# ROI item 13 (fast, always-on companion to the exhaustive flag_matrix.sh / CI). Compiles the two
# modules that share the HKFScrubActiveConfig symbol across all four KEYSCRUB x HKF combinations and
# partial-links them (`ld -r`, which fails on a multiply-defined symbol). The negative control
# re-injects the historical broken guard and asserts the KEYSCRUB-only combo collides.
SC_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SC_CC="$c"; break; fi; done
SC_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
SC_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
sc_combo() { # $1..$n = -D flags ; compiles both modules + ld -r ; echo OK/COLLIDE
	local src="$1"; shift
	"$SC_CC" -O0 $SC_WNO $SC_NOASM "$@" $INC -c "$SRCROOT/Common/KeyScrub.c" -o /tmp/sc_ks.o 2>/dev/null || { echo BUILDFAIL; return; }
	"$SC_CC" -O0 $SC_WNO $SC_NOASM "$@" $INC -x c -c "$src" -o /tmp/sc_hkf.o 2>/dev/null || { echo BUILDFAIL; return; }
	if ld -r /tmp/sc_ks.o /tmp/sc_hkf.o -o /tmp/sc_all.o 2>/dev/null; then echo OK; else echo COLLIDE; fi
}
if [ -n "$SC_CC" ] && command -v ld >/dev/null 2>&1; then
	REALHKF="$SRCROOT/Common/HardwareKeyFactor.c"
	BROKENHKF="/tmp/sc_broken_hkf.c"
	sed 's/#if defined(VC_ENABLE_KEYSCRUB) && defined(VC_ENABLE_HKF)/#if defined(VC_ENABLE_KEYSCRUB)/' "$REALHKF" > "$BROKENHKF"
	r_none=$(sc_combo "$REALHKF")
	r_ks=$(sc_combo   "$REALHKF" -DVC_ENABLE_KEYSCRUB)
	r_hkf=$(sc_combo  "$REALHKF" -DVC_ENABLE_HKF)
	r_both=$(sc_combo "$REALHKF" -DVC_ENABLE_KEYSCRUB -DVC_ENABLE_HKF)
	b_ks=$(sc_combo   "$BROKENHKF" -DVC_ENABLE_KEYSCRUB)   # negative control: MUST collide
	echo "    combos (real):  none=$r_none  KEYSCRUB=$r_ks  HKF=$r_hkf  both=$r_both"
	echo "    negative control (broken guard, KEYSCRUB-only): $b_ks"
	if [ "$r_none" = OK ] && [ "$r_ks" = OK ] && [ "$r_hkf" = OK ] && [ "$r_both" = OK ] && [ "$b_ks" = COLLIDE ]; then
		echo "    MATCH: all real KEYSCRUB x HKF combos link cleanly; broken guard proven to collide"
	else
		echo "    SYMBOL-COLLISION CHECK FAILED (real=$r_none/$r_ks/$r_hkf/$r_both negctl=$b_ks)"; exit 1
	fi
	rm -f "$BROKENHKF"
else
	skip_step " no compiler or ld available for the symbol-collision check"
fi

echo ""
echo "[52] Log-redaction: secrets loaded into config never appear in the diagnostic/verbose surface"
# ROI item 14. Drives the real HKF integration (HKFApplyIfConfigured) with DISTINCTIVE sentinel secrets
# in the config (reconstructed factor secret + FIDO2 PIN), then emits the verbose config summary a
# --verbose/debug mode would print, and greps ALL output for the sentinels — a clean build must leak
# none. The -DVC_LOGLEAK build is the negative control: the summary dumps the PIN + secret, and the
# grep MUST find them (proving the check has teeth; a real redaction regression looks identical).
LR_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then LR_CC="$c"; break; fi; done
LR_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
LR_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
LR_DEF="-DVC_ENABLE_HKF -DVC_ENABLE_KEYSCRUB"
if [ -n "$LR_CC" ] \
   && "$LR_CC" -O2 $LR_WNO $LR_NOASM $LR_DEF $INC -c "$SRCROOT/Common/HardwareKeyFactor.c" -o /tmp/lr_hkf.o 2>/tmp/lr_log \
   && "$LR_CC" -O2 $LR_WNO $LR_DEF $INC "$HERE/log_redaction_test.c" /tmp/lr_hkf.o -o /tmp/lr_norm 2>>/tmp/lr_log \
   && "$LR_CC" -O2 $LR_WNO $LR_DEF -DVC_LOGLEAK $INC "$HERE/log_redaction_test.c" /tmp/lr_hkf.o -o /tmp/lr_leak 2>>/tmp/lr_log; then
	/tmp/lr_norm > /tmp/lr_norm.txt
	/tmp/lr_leak > /tmp/lr_leak.txt
	PIN="REDACT_SENTINEL_PIN_7c1f9a2b"
	RAWHEX="$(python3 -c "print('REDACT_SENTINEL_RAW_4e8d1c60'.encode().hex())")"
	norm_pin=$(grep -c "$PIN" /tmp/lr_norm.txt || true); norm_hex=$(grep -c "$RAWHEX" /tmp/lr_norm.txt || true)
	leak_pin=$(grep -c "$PIN" /tmp/lr_leak.txt || true); leak_hex=$(grep -c "$RAWHEX" /tmp/lr_leak.txt || true)
	echo "    clean build:   pin-sentinel=$norm_pin  secret-hex=$norm_hex   (must be 0/0)"
	echo "    LOGLEAK build: pin-sentinel=$leak_pin  secret-hex=$leak_hex   (negative control, must be >=1/>=1)"
	if [ "$norm_pin" -eq 0 ] && [ "$norm_hex" -eq 0 ] && [ "$leak_pin" -ge 1 ] && [ "$leak_hex" -ge 1 ]; then
		echo "    MATCH: no secret reaches the diagnostic surface; grep proven to catch a real leak"
	else
		echo "    LOG-REDACTION FAILED (clean=$norm_pin/$norm_hex leak=$leak_pin/$leak_hex)"; exit 1
	fi
else
	skip_step " no compiler accepted the sources for the log-redaction test (see /tmp/lr_log)"
fi

echo ""
echo "[53] Per-slot policy: read-only + expiry + max-attempts over real KeyslotStore.c (ROI item 15)"
# Behavioural test of the shipping VC_ENABLE_KEYSLOT_POLICY code (KeyslotAddPolicy / KeyslotOpenPolicy
# / KeyslotOpenAtPolicy), each policy with a negative control, plus a v1-legacy byte-compat check and
# the honest rollback-limitation demo. Layer 1: keyslot_policy_reference.py independently computes the
# v2 payload layout (flags||expiryUnix_be||vmk), diffed byte-for-byte against the REF lines.
KPP_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KPP_CC="$c"; break; fi; done
KPP_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
KPP_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KPP_GC="-ffunction-sections -fdata-sections"
KPP_DEF="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_KEYSLOT_POLICY"
KPP_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$KPP_CC" ] \
   && "$KPP_CC" -O2 $KPP_WNO $KPP_NOASM $KPP_GC $KPP_DEF $KPP_INC -c "$SRCROOT/Common/Keyslot.c"      -o /tmp/kpp_ks.o    2>/tmp/kpp_log \
   && "$KPP_CC" -O2 $KPP_WNO $KPP_NOASM $KPP_GC $KPP_DEF $KPP_INC -c "$SRCROOT/Common/KeyslotStore.c" -o /tmp/kpp_store.o 2>>/tmp/kpp_log \
   && "$KPP_CC" -O2 $KPP_WNO $KPP_NOASM $KPP_GC $KPP_DEF $KPP_INC -c "$SRCROOT/Common/AfSplit.c"      -o /tmp/kpp_af.o    2>>/tmp/kpp_log \
   && "$KPP_CC" -O2 $KPP_WNO $KPP_NOASM $KPP_GC $KPP_INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/kpp_sha.o 2>>/tmp/kpp_log \
   && "$KPP_CC" -O2 $KPP_WNO $KPP_NOASM $KPP_GC $KPP_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/kpp_cc.o 2>>/tmp/kpp_log \
   && "$KPP_CC" -O2 $KPP_WNO $KPP_DEF $KPP_INC "$HERE/keyslot_policy_test.c" \
        /tmp/kpp_ks.o /tmp/kpp_store.o /tmp/kpp_af.o /tmp/kpp_sha.o /tmp/kpp_cc.o -Wl,--gc-sections -o /tmp/keyslot_policy_test 2>>/tmp/kpp_log; then
	if /tmp/keyslot_policy_test > /tmp/kpp_c.txt; then cat /tmp/kpp_c.txt; else cat /tmp/kpp_c.txt; echo "    KEYSLOT POLICY FAILED"; exit 1; fi
	python3 "$HERE/keyslot_policy_reference.py" > /tmp/kpp_py.txt
	grep '^REF' /tmp/kpp_c.txt > /tmp/kpp_c_ref.txt
	if diff -q /tmp/kpp_c_ref.txt /tmp/kpp_py.txt >/dev/null; then
		echo "    MATCH: v2 payload layout (real KeyslotStore object) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/kpp_c_ref.txt /tmp/kpp_py.txt; exit 1
	fi
else
	skip_step " no compiler accepted the sources for the keyslot-policy test (see /tmp/kpp_log)"
fi

echo ""
echo "[54] Self-test on mount: KATs for the fork's crypto primitives (ROI item 17)"
# Runs the shipping VcForkSelfTest (SHA3-512/SHA-256/t1ha2 KATs) over the REAL compiled Crypto objects;
# a factored/keyslot mount must call this and fail closed on a non-zero result. Negative control: a
# second build with -DVC_SELFTEST_CORRUPT perturbs one expected value and the self-test MUST flag it.
ST_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then ST_CC="$c"; break; fi; done
ST_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
ST_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
ST_GC="-ffunction-sections -fdata-sections"
ST_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$ST_CC" ] \
   && "$ST_CC" -O2 $ST_WNO $ST_NOASM $ST_GC $ST_INC -c "$SRCROOT/Crypto/Sha3.c"  -o /tmp/st_sha3.o 2>/tmp/st_log \
   && "$ST_CC" -O2 $ST_WNO $ST_NOASM $ST_GC $ST_INC -c "$SRCROOT/Crypto/Sha2.c"  -o /tmp/st_sha2.o 2>>/tmp/st_log \
   && "$ST_CC" -O2 $ST_WNO $ST_NOASM $ST_GC $ST_INC -c "$SRCROOT/Crypto/t1ha2.c" -o /tmp/st_t1.o   2>>/tmp/st_log \
   && "$ST_CC" -O2 $ST_WNO $ST_NOASM $ST_GC -DVC_ENABLE_SELFTEST $ST_INC -c "$SRCROOT/Common/SelfTest.c" -o /tmp/st_self.o 2>>/tmp/st_log \
   && "$ST_CC" -O2 $ST_WNO $ST_NOASM $ST_GC -DVC_ENABLE_SELFTEST -DVC_SELFTEST_CORRUPT $ST_INC -c "$SRCROOT/Common/SelfTest.c" -o /tmp/st_self_c.o 2>>/tmp/st_log \
   && "$ST_CC" -O2 $ST_WNO -DVC_ENABLE_SELFTEST $ST_INC "$HERE/selftest_test.c" /tmp/st_self.o /tmp/st_sha3.o /tmp/st_sha2.o /tmp/st_t1.o -Wl,--gc-sections -o /tmp/st_norm 2>>/tmp/st_log \
   && "$ST_CC" -O2 $ST_WNO -DVC_ENABLE_SELFTEST -DVC_SELFTEST_CORRUPT $ST_INC "$HERE/selftest_test.c" /tmp/st_self_c.o /tmp/st_sha3.o /tmp/st_sha2.o /tmp/st_t1.o -Wl,--gc-sections -o /tmp/st_corr 2>>/tmp/st_log; then
	if /tmp/st_norm; then :; else echo "    SELF-TEST FAILED (real KATs did not pass)"; exit 1; fi
	if /tmp/st_corr; then echo "    MATCH: fork-primitive KATs pass; negative control (corrupted build) is caught"
	else echo "    SELF-TEST NEG-CONTROL FAILED (corruption not detected)"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the self-test (see /tmp/st_log)"
fi

echo ""
echo "[55] Verification-coverage display: machine-verified vs documented (ROI item 19)"
# coverage_report.sh separates what the suite actually verifies from claims that need real hardware /
# wx / kernel — directly addressing the "all green" problem. --check asserts the verified list is
# derived live from the suite (no hand-maintained drift) and that documented-only claims are not
# listed as verified; --check-negctl is the negative control (an injected real-hardware "step" must be
# detected as documented-only).
if "$HERE/coverage_report.sh" --check && "$HERE/coverage_report.sh" --check-negctl; then
	echo "    MATCH: coverage classifier is live-derived + honest; negative control detects a mislabeled claim"
else
	echo "    COVERAGE-DISPLAY CHECK FAILED"; exit 1
fi

echo ""
echo "[56] Keyslot parser fuzz under ASan+UBSan (ROI item 31)"
# Feeds thousands of malformed/random KeyslotAreas + randomized in-bounds configs to the REAL
# KeyslotOpen/OpenAt/Count/Revoke (+ policy variants); ASan/UBSan are the oracle for any OOB / UB.
# Needs a sanitizer-capable toolchain (gcc ships libasan; a clang without compiler-rt is skipped).
# Negative control: a parser that trusts a record-supplied length reads OOB and MUST fault under ASan.
FZ_SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -g"
FZ_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
FZ_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
FZ_DEF="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_KEYSLOT_POLICY"
FZ_INC="$INC -I$SRCROOT/Crypto"
FZ_SRC="$SRCROOT/Common/Keyslot.c $SRCROOT/Common/KeyslotStore.c $SRCROOT/Common/AfSplit.c $SRCROOT/Crypto/Sha2.c $SRCROOT/Crypto/chacha256.c"
FZ_CC=""
for c in gcc-14 gcc-13 gcc cc clang; do
	command -v "$c" >/dev/null 2>&1 || continue
	printf 'int main(){return 0;}\n' > /tmp/fz_probe.c
	if "$c" -fsanitize=address,undefined /tmp/fz_probe.c -o /tmp/fz_probe 2>/dev/null; then FZ_CC="$c"; break; fi
done
if [ -n "$FZ_CC" ] \
   && "$FZ_CC" -O1 $FZ_WNO $FZ_NOASM $FZ_SAN $FZ_DEF $FZ_INC "$HERE/keyslot_fuzz.c" $FZ_SRC -o /tmp/keyslot_fuzz 2>/tmp/fz_log \
   && "$FZ_CC" -O1 $FZ_WNO $FZ_NOASM $FZ_SAN -DVC_FUZZ_NEGCTL $FZ_DEF $FZ_INC "$HERE/keyslot_fuzz.c" $FZ_SRC -o /tmp/keyslot_fuzz_nc 2>>/tmp/fz_log; then
	if /tmp/keyslot_fuzz; then :; else echo "    KEYSLOT FUZZ FAILED (sanitizer fault on real parser)"; exit 1; fi
	if /tmp/keyslot_fuzz_nc >/tmp/fz_nc.out 2>&1; then
		echo "    NEG-CONTROL FAILED: the deliberately OOB parser did not fault under ASan"; cat /tmp/fz_nc.out; exit 1
	else
		echo "    MATCH: real keyslot parser survives fuzzing clean; ASan proven to catch an OOB parser ($FZ_CC)"
	fi
else
	skip_step " no sanitizer-capable compiler (gcc libasan) available for the keyslot fuzz (see /tmp/fz_log)"
fi

echo ""
echo "[57] Deniable-extent geometry fuzz under ASan+UBSan (ROI item 32)"
# Fuzzes KeyslotAreaBindDeniable with adversarial volume geometry (overlapping/reversed/near-overflow
# freeStart/freeEnd/hiddenReservedStart) and asserts every ACCEPTED window stays within the free extent
# and NEVER reaches into the hidden-volume region (the security invariant), plus bounded stdio over a
# real header-slack window under the sanitizers. Negative control: a clamp that ignores the hidden
# start yields a window into hidden space, which the invariant check must flag.
AF_SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -g"
AF_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
AF_DEF="-DVC_ENABLE_KEYSLOTS"
AF_CC=""
for c in gcc-14 gcc-13 gcc cc clang; do
	command -v "$c" >/dev/null 2>&1 || continue
	printf 'int main(){return 0;}\n' > /tmp/af_probe.c
	if "$c" -fsanitize=address,undefined /tmp/af_probe.c -o /tmp/af_probe 2>/dev/null; then AF_CC="$c"; break; fi
done
if [ -n "$AF_CC" ] \
   && "$AF_CC" -O1 $AF_WNO $AF_SAN $AF_DEF $INC "$HERE/areafile_fuzz.c" "$SRCROOT/Common/KeyslotAreaFile.c" -o /tmp/areafile_fuzz 2>/tmp/af_log \
   && "$AF_CC" -O1 $AF_WNO $AF_SAN -DVC_AREAFILE_NEGCTL $AF_DEF $INC "$HERE/areafile_fuzz.c" "$SRCROOT/Common/KeyslotAreaFile.c" -o /tmp/areafile_fuzz_nc 2>>/tmp/af_log; then
	if /tmp/areafile_fuzz; then :; else echo "    AREAFILE FUZZ FAILED (deniable window escaped or sanitizer fault)"; exit 1; fi
	if /tmp/areafile_fuzz_nc; then echo "    MATCH: deniable placement never reaches hidden space under fuzzing; oracle catches a broken clamp ($AF_CC)"
	else echo "    AREAFILE NEG-CONTROL FAILED (broken clamp not detected)"; exit 1; fi
else
	skip_step " no sanitizer-capable compiler (gcc libasan) for the areafile fuzz (see /tmp/af_log)"
fi

echo ""
echo "[58] Sanitizer sweep: behavioural harnesses under ASan+UBSan (ROI item 33)"
# Extends ASan+UBSan coverage (items 31/32 sanitize the parsers) across the keyslot lifecycle, per-slot
# policy, KeyScrub, duress, and Shamir harnesses. sanitize.sh includes its own negative control (a
# heap overflow must be caught, so an inactive sanitizer also fails). Skips if no gcc libasan.
if out="$("$HERE/sanitize.sh" 2>&1)"; then
	echo "$out" | sed 's/^/    /'
	echo "    MATCH: behavioural harnesses clean under ASan+UBSan (sanitizer proven active)"
elif [ $? -eq 42 ]; then
	skip_step " no sanitizer-capable compiler (gcc libasan) for the sanitizer sweep"
else
	echo "$out" | sed 's/^/    /'; echo "    SANITIZER SWEEP FAILED"; exit 1
fi

echo ""
echo "[59] dudect timing screen: DuressTokenMatch constant-time tag compare (ROI item 34)"
# Extends the dudect coverage (Shamir GF(2^8) step [41]-era, keyslot path) to the duress tag compare.
# Self-validating Welch t-test: it MUST flag a leaky early-exit compare and CLEAR the real
# OR-accumulate DuressTokenMatch (asserting the contrast, not an absolute cycle count).
DD_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then DD_CC="$c"; break; fi; done
DD_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
DD_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
DD_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$DD_CC" ] \
   && "$DD_CC" -O2 $DD_WNO $DD_NOASM -DVC_ENABLE_DURESS $DD_INC "$HERE/duress_dudect_test.c" "$SRCROOT/Common/DuressToken.c" "$SRCROOT/Crypto/Sha2.c" -lm -o /tmp/duress_dudect 2>/tmp/dd_log; then
	if /tmp/duress_dudect > /tmp/dd_c.txt; then cat /tmp/dd_c.txt
		echo "    MATCH: dudect flags a leaky tag compare and clears the real constant-time DuressTokenMatch"
	else cat /tmp/dd_c.txt; echo "    DURESS DUDECT FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the duress dudect screen (see /tmp/dd_log)"
fi

echo ""
echo "[60] Degenerate-input property tests: thresholds, duplicate-x, ranges, zero-length password (ROI item 35)"
# Pins the specific degenerate cases a random fuzzer rarely hits: threshold==n, duplicate x-coordinates
# (a Lagrange divide-by-zero if unguarded -> must return SHAMIR_ERR_PARAM), parameter-range rejection,
# boundary secrets, and zero-length keyslot passwords. Explicit properties over the REAL Shamir.c /
# KeyslotStore.c; each degenerate assertion is its own control (the "must NOT recover" / "must reject"
# side). Built under ASan+UBSan when available so an unguarded div-by-zero also traps.
PT_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
PT_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
PT_INC="$INC -I$SRCROOT/Crypto"
PT_SRC="$SRCROOT/Common/Shamir.c $SRCROOT/Common/Keyslot.c $SRCROOT/Common/KeyslotStore.c $SRCROOT/Common/AfSplit.c $SRCROOT/Crypto/Sha2.c $SRCROOT/Crypto/chacha256.c"
PT_SAN=""
for c in gcc-14 gcc-13 gcc; do command -v "$c" >/dev/null 2>&1 || continue
	printf 'int main(){return 0;}\n' > /tmp/pt_probe.c
	if "$c" -fsanitize=address,undefined /tmp/pt_probe.c -o /tmp/pt_probe 2>/dev/null; then PT_CC="$c"; PT_SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -g"; break; fi
done
[ -n "$PT_SAN" ] || { for c in clang gcc cc; do command -v "$c" >/dev/null 2>&1 && { PT_CC="$c"; break; }; done; }
if [ -n "${PT_CC:-}" ] \
   && "$PT_CC" -O1 $PT_WNO $PT_NOASM $PT_SAN -DVC_ENABLE_KEYSLOTS $PT_INC "$HERE/property_test.c" $PT_SRC -o /tmp/property_test 2>/tmp/pt_log; then
	if /tmp/property_test > /tmp/pt_c.txt; then cat /tmp/pt_c.txt
		echo "    MATCH: degenerate-input properties hold${PT_SAN:+ (under ASan+UBSan)}"
	else cat /tmp/pt_c.txt; echo "    PROPERTY TESTS FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the property tests (see /tmp/pt_log)"
fi

echo ""
echo "[61] Secrets scan: no credentials in the tree (ROI item 38)"
# scripts/secrets-scan.sh (also a .githooks pre-commit hook + CI job) scans for private keys and
# cloud/service tokens. --self-test is the built-in control: a planted AWS-key-shaped secret MUST be
# caught and a file of crypto KAT hex MUST NOT be flagged (no false positive on the repo's test data).
if "$SRCROOT/../scripts/secrets-scan.sh" --self-test >/tmp/ss_c.txt 2>&1 && "$SRCROOT/../scripts/secrets-scan.sh" >>/tmp/ss_c.txt 2>&1; then
	sed 's/^/    /' /tmp/ss_c.txt
	echo "    MATCH: no secrets in the tracked tree; scanner catches a planted secret, ignores KAT hex"
else
	sed 's/^/    /' /tmp/ss_c.txt; echo "    SECRETS SCAN FAILED (a credential-like pattern was found, or the self-test control broke)"; exit 1
fi

echo ""
echo "[62] Static analysis: clang-tidy over the fork modules (ROI item 37)"
# Curated high-signal check set (.clang-tidy): the clang static analyzer + a small bugprone subset,
# WarningsAsErrors. Skips if clang-tidy is absent. CodeQL runs separately (.github/workflows/codeql.yml).
if command -v clang-tidy >/dev/null 2>&1; then
	if out="$("$SRCROOT/../scripts/clang-tidy-fork.sh" 2>&1)"; then
		echo "$out" | sed 's/^/    /'
		echo "    MATCH: all fork Common modules pass clang-tidy (static analyzer) clean"
	else
		echo "$out" | sed 's/^/    /'; echo "    CLANG-TIDY FAILED"; exit 1
	fi
else
	skip_step " clang-tidy not installed (static-analysis step)"
fi

echo ""
echo "[63] Verifiable keyslot shredding + attestation (ROI item 41)"
# KeyslotShred overwrites the whole slot (ciphertext + AF stripes) and returns an attestation over what
# ACTUALLY landed on the medium. Proves: shredded slot won't open, no verbatim ciphertext remnant, and
# the attestation is independently reproducible from the observed before/after hashes. Negative control:
# a weak "mark-free" (clear only the magic) leaves the old ciphertext recoverable verbatim.
KH_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KH_CC="$c"; break; fi; done
KH_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
KH_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KH_GC="-ffunction-sections -fdata-sections"
KH_DEF="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_KEYSLOT_SHRED"
KH_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$KH_CC" ] \
   && "$KH_CC" -O2 $KH_WNO $KH_NOASM $KH_GC $KH_DEF $KH_INC "$HERE/keyslot_shred_test.c" \
        "$SRCROOT/Common/Keyslot.c" "$SRCROOT/Common/KeyslotStore.c" "$SRCROOT/Common/AfSplit.c" \
        "$SRCROOT/Crypto/Sha2.c" "$SRCROOT/Crypto/chacha256.c" -Wl,--gc-sections -o /tmp/keyslot_shred_test 2>/tmp/kh_log; then
	if /tmp/keyslot_shred_test > /tmp/kh_c.txt; then cat /tmp/kh_c.txt
		echo "    MATCH: shred is unrecoverable + attestable; weak mark-free demonstrably leaves a remnant"
	else cat /tmp/kh_c.txt; echo "    KEYSLOT SHRED FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the keyslot-shred test (see /tmp/kh_log)"
fi

echo ""
echo "[64] Error taxonomy + stable exit codes (ROI item 47)"
# Verifies the scriptable contract over the real VcStatus.c: every status has a name + description +
# exit code, error exit codes are distinct and non-zero, names are unique, out-of-range falls back
# safely. The REF lines (name -> exit code) are diffed byte-for-byte against status_reference.py, which
# independently pins the contract — a renumber breaks the diff (the stability guarantee's teeth).
SS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then SS_CC="$c"; break; fi; done
if [ -n "$SS_CC" ] && "$SS_CC" -O2 -Wno-implicit-function-declaration -DVC_ENABLE_STATUS $INC "$HERE/status_test.c" "$SRCROOT/Common/VcStatus.c" -o /tmp/status_test 2>/tmp/ss_log; then
	if /tmp/status_test > /tmp/ss_c.txt; then grep -v '^REF' /tmp/ss_c.txt
		python3 "$HERE/status_reference.py" > /tmp/ss_py.txt
		grep '^REF' /tmp/ss_c.txt > /tmp/ss_c_ref.txt
		if diff -q /tmp/ss_c_ref.txt /tmp/ss_py.txt >/dev/null; then
			echo "    MATCH: exit-code contract (real VcStatus.c) == independent python pin"
		else echo "    MISMATCH"; diff /tmp/ss_c_ref.txt /tmp/ss_py.txt; exit 1; fi
	else grep -v '^REF' /tmp/ss_c.txt; echo "    STATUS TAXONOMY FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the status taxonomy test (see /tmp/ss_log)"
fi

echo ""
echo "[65] --json output correctness + escaping (ROI item 48)"
# Emits JSON via the real VcJson.c + VcStatus.c; python's own parser (json_reference.py) is the oracle.
# Checks valid JSON, round-trip, and that a hostile string value (quotes/backslash/newline + a fake
# injected field) is ESCAPED, not injected. Negative control: a naive unescaped emitter whose output
# the parser must reject -> proves the escaping is load-bearing.
JS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then JS_CC="$c"; break; fi; done
JS_DEF="-DVC_ENABLE_JSON -DVC_ENABLE_STATUS"
if [ -n "$JS_CC" ] \
   && "$JS_CC" -O2 -Wno-implicit-function-declaration $JS_DEF $INC "$HERE/json_test.c" "$SRCROOT/Common/VcJson.c" "$SRCROOT/Common/VcStatus.c" -o /tmp/json_test 2>/tmp/js_log \
   && "$JS_CC" -O2 -Wno-implicit-function-declaration $JS_DEF -DVC_JSON_NEGCTL $INC "$HERE/json_test.c" "$SRCROOT/Common/VcJson.c" "$SRCROOT/Common/VcStatus.c" -o /tmp/json_test_nc 2>>/tmp/js_log; then
	/tmp/json_test | sed 's/^/    /'
	if /tmp/json_test | python3 "$HERE/json_reference.py" >/tmp/js_ok.txt 2>&1 \
	   && /tmp/json_test_nc | python3 "$HERE/json_reference.py" --negctl >/tmp/js_nc.txt 2>&1; then
		sed 's/^/    /' /tmp/js_ok.txt; sed 's/^/    /' /tmp/js_nc.txt
		echo "    MATCH: --json output is valid + escapes hostile values; negative control (unescaped) is rejected"
	else
		sed 's/^/    /' /tmp/js_ok.txt; sed 's/^/    /' /tmp/js_nc.txt; echo "    JSON OUTPUT FAILED"; exit 1
	fi
else
	skip_step " no compiler accepted the sources for the json test (see /tmp/js_log)"
fi

echo ""
echo "[66] Integrity-checked header/keyslot-area backup (ROI item 44)"
# HeaderBackupCreate/Verify/Restore over a real populated keyslot area: backup -> corrupt the live area
# -> restore recovers the slots. Negative controls: a flipped byte in the backup fails verification
# (HB_ERR_INTEGRITY) and Restore REFUSES it, leaving the area untouched; bad magic / truncation are
# rejected as HB_ERR_FORMAT.
HB_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then HB_CC="$c"; break; fi; done
HB_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
HB_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
HB_GC="-ffunction-sections -fdata-sections"
HB_DEF="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_HEADER_BACKUP"
HB_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$HB_CC" ] \
   && "$HB_CC" -O2 $HB_WNO $HB_NOASM $HB_GC $HB_DEF $HB_INC "$HERE/header_backup_test.c" \
        "$SRCROOT/Common/Keyslot.c" "$SRCROOT/Common/KeyslotStore.c" "$SRCROOT/Common/AfSplit.c" \
        "$SRCROOT/Common/HeaderBackup.c" "$SRCROOT/Crypto/Sha2.c" "$SRCROOT/Crypto/chacha256.c" \
        -Wl,--gc-sections -o /tmp/header_backup_test 2>/tmp/hb_log; then
	if /tmp/header_backup_test > /tmp/hb_c.txt; then cat /tmp/hb_c.txt
		echo "    MATCH: backup restores the area and integrity detects/refuses corruption"
	else cat /tmp/hb_c.txt; echo "    HEADER BACKUP FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the header-backup test (see /tmp/hb_log)"
fi

echo ""
echo "[67] systemd unit hardening lint (ROI item 49)"
# The network-share unlock server is a secret-bearing network daemon; its shipped unit
# (dist/systemd/vc-netshared.service) must actually drop privilege. systemd_hardening_lint.sh
# checks it two ways: a required-directive check AND `systemd-analyze security --offline`
# exposure score (when present). Negative control: a unit with the hardening stripped must FAIL
# the directive check and score a worse exposure. The lint is self-contained (no build needed).
if "$HERE/systemd_hardening_lint.sh" | sed 's/^/    /'; then
	echo "    MATCH: shipped systemd unit is hardened (directives + systemd-analyze); stripped unit fails"
else
	echo "    SYSTEMD HARDENING LINT FAILED"; exit 1
fi

echo ""
echo "[68] Multi-token OR-set: any one of N enrolled tokens unlocks (ROI item 45)"
# HkfOrSet over real Keyslot + HardwareKeyFactor objects: enroll N RAW_SECRET (salt-bound) tokens
# each wrapping ONE VMK; any single enrolled token recovers the exact VMK. Negative controls: a
# never-enrolled token opens nothing; after revoking one token's slot, that token stops working
# while every other token still opens (per-token, not all-or-nothing).
OS_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then OS_CC="$c"; break; fi; done
OS_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
OS_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
OS_DEF="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_HKF -DVC_ENABLE_HKF_SALT_BIND -DVC_ENABLE_HKF_ORSET"
OS_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$OS_CC" ] \
   && "$OS_CC" -O2 $OS_WNO $OS_NOASM $OS_DEF $OS_INC "$HERE/hkf_orset_test.c" \
        "$SRCROOT/Common/HkfOrSet.c" "$SRCROOT/Common/HardwareKeyFactor.c" "$SRCROOT/Common/Keyslot.c" \
        "$SRCROOT/Common/KeyslotStore.c" "$SRCROOT/Common/AfSplit.c" "$SRCROOT/Common/Shamir.c" \
        "$SRCROOT/Crypto/Sha2.c" "$SRCROOT/Crypto/chacha256.c" -o /tmp/hkf_orset_test 2>/tmp/os_log; then
	if /tmp/hkf_orset_test > /tmp/os_c.txt; then cat /tmp/os_c.txt
		echo "    MATCH: any one enrolled token unlocks; non-enrolled fails; revoke is per-token"
	else cat /tmp/os_c.txt; echo "    OR-SET FAILED"; exit 1; fi
else
	skip_step " no compiler accepted the sources for the OR-set test (see /tmp/os_log)"
fi

echo ""
echo "[69] Wycheproof-style HMAC-SHA256 edge-case vectors (ROI item 36)"
# HMAC-SHA256 underpins salt-binding / duress / keyslot-MAC / Shamir-share-MAC. wycheproof_vectors.py
# emits adversarial edge vectors (key/msg at the SHA-256 block boundaries 0/1/32/64/65/128 & 55/56/
# 63/64/65/127, all-zero/all-0xff keys, plus flipped-bit and truncated INVALID tags); their expected
# tags come from python's own hmac (oracle). wycheproof_test.c recomputes each with the real in-tree
# Sha2.c and enforces valid==match / invalid==reject. Negative control (-DWP_NEGCTL): a broken HMAC
# that truncates over-long keys instead of hashing them MUST fail the key=65/128 boundary vectors.
WP_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then WP_CC="$c"; break; fi; done
WP_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
WP_INC="$INC -I$SRCROOT/Crypto -I/tmp"
if [ -n "$WP_CC" ] && python3 "$HERE/wycheproof_vectors.py" --emit-header > /tmp/wycheproof_vectors.h 2>/tmp/wp_gen.log \
   && "$WP_CC" -O2 -Wno-implicit-function-declaration $WP_NOASM $WP_INC "$HERE/wycheproof_test.c" "$SRCROOT/Crypto/Sha2.c" -o /tmp/wp_test 2>/tmp/wp_log \
   && "$WP_CC" -O2 -Wno-implicit-function-declaration -DWP_NEGCTL $WP_NOASM $WP_INC "$HERE/wycheproof_test.c" "$SRCROOT/Crypto/Sha2.c" -o /tmp/wp_nc 2>>/tmp/wp_log; then
	if /tmp/wp_test > /tmp/wp_c.txt && /tmp/wp_nc > /tmp/wp_nc.txt; then
		sed 's/^/    /' /tmp/wp_c.txt; sed 's/^/    /' /tmp/wp_nc.txt
		echo "    MATCH: real Sha2.c HMAC-SHA256 passes the edge vectors; broken HMAC fails the boundary cases"
	else
		sed 's/^/    /' /tmp/wp_c.txt; sed 's/^/    /' /tmp/wp_nc.txt; echo "    WYCHEPROOF VECTORS FAILED"; exit 1
	fi
else
	skip_step " no compiler/python for the wycheproof edge-vector test (see /tmp/wp_log, /tmp/wp_gen.log)"
fi

echo ""
echo "[70] Argon2id auto-calibration to a time budget (ROI item 10)"
# Argon2IterationsForBudget (pure policy) is diffed byte-for-byte vs argon2_calibrate_reference.py;
# Argon2CalibrateToTime runs a REAL Argon2id probe over the compiled Argon2, measures a positive
# per-iteration cost, and yields iteration counts that are monotone in the budget and floor/cap-clamped,
# with a back-to-back derive at the larger budget taking longer. Negative control: a budget-ignoring
# policy must FAIL the property battery. Reuses step [11]'s Argon2 link recipe.
CB_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then CB_CC="$c"; break; fi; done
CB_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier -Wno-unused-command-line-argument"
CB_GC="-ffunction-sections -fdata-sections"
CB_INC="$INC -I$SRCROOT/Crypto -I$SRCROOT/Crypto/Argon2/include -I$SRCROOT/Crypto/Argon2/src"
CB_ARG="$SRCROOT/Crypto/Argon2/src"
printf 'volatile int g_hasSSE2=1,g_hasAVX2=0,g_hasSSE42=0,g_hasAVX=0,g_hasSSSE3=0,g_hasAESNI=0,g_hasSHA256=0,g_isIntel=0,g_isAMD=0,g_hasSSE41=0,g_hasRDRAND=0,g_hasRDSEED=0;\n' > /tmp/cb_stub.c
if [ -n "$CB_CC" ] \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS $CB_INC -c "$CB_ARG/argon2.c" -o /tmp/cb_argon2.o 2>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS $CB_INC -c "$CB_ARG/core.c"   -o /tmp/cb_core.o   2>>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS $CB_INC -c "$CB_ARG/ref.c"    -o /tmp/cb_ref.o    2>>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS $CB_INC -c "$CB_ARG/blake2/blake2b.c" -o /tmp/cb_b2.o 2>>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS -msse2 $CB_INC -c "$CB_ARG/opt_sse2.c" -o /tmp/cb_sse2.o 2>>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS -mavx2 -msse2 $CB_INC -c "$CB_ARG/opt_avx2.c" -o /tmp/cb_avx2.o 2>>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO $CB_GC -DARGON2_NO_THREADS -DVC_ENABLE_ARGON2_PARAMS $CB_INC -c "$SRCROOT/Common/Pkcs5.c" -o /tmp/cb_pkcs5.o 2>>/tmp/cb.log \
   && "$CB_CC" -O2 $CB_WNO -DARGON2_NO_THREADS -DVC_ENABLE_ARGON2_PARAMS $CB_INC "$HERE/argon2_calibrate_test.c" /tmp/cb_stub.c \
        /tmp/cb_pkcs5.o /tmp/cb_argon2.o /tmp/cb_core.o /tmp/cb_ref.o /tmp/cb_b2.o /tmp/cb_sse2.o /tmp/cb_avx2.o \
        -Wl,--gc-sections -o /tmp/cb_test 2>>/tmp/cb.log; then
	/tmp/cb_test > /tmp/cb_c.txt; grep -v '^REF' /tmp/cb_c.txt | sed 's/^/    /'
	grep '^REF' /tmp/cb_c.txt > /tmp/cb_c_ref.txt
	python3 "$HERE/argon2_calibrate_reference.py" > /tmp/cb_py.txt
	if diff -q /tmp/cb_c_ref.txt /tmp/cb_py.txt >/dev/null && grep -q '^PASS' /tmp/cb_c.txt; then
		echo "    MATCH: calibration policy == python; real Argon2 probe monotone/timed; negctl fires"
	else
		echo "    MISMATCH / calibration failed"; diff /tmp/cb_c_ref.txt /tmp/cb_py.txt | head; exit 1
	fi
else
	skip_step " no compiler for the argon2 calibration test (see /tmp/cb.log)"
fi

echo ""
echo "[71] Security-posture report reflects compiled features (ROI item 18)"
# VcPosture emits a JSON report whose booleans come from the real VC_ENABLE_* compile guards.
# Built three ways: (A) keyslots+duress ON -> those true, rest false, features_on=2; (B) stock ->
# all false, features_on=0, hardened=false, and the JSON validates in python's parser; (C) negative
# control -DVP_NEGCTL built with NO features LIES (keyslots:true) -> proving (B)'s false values
# genuinely track the guards, not a hardcoded list.
PO_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then PO_CC="$c"; break; fi; done
PO_SRC="$SRCROOT/Common/VcPosture.c $SRCROOT/Common/VcJson.c"
PO_BASE="-DVC_ENABLE_JSON -DVC_ENABLE_POSTURE"
if [ -n "$PO_CC" ] \
   && "$PO_CC" -O2 -w $PO_BASE -DVC_ENABLE_KEYSLOTS -DVC_ENABLE_DURESS $INC "$HERE/vcposture_test.c" $PO_SRC -o /tmp/po_A 2>/tmp/po.log \
   && "$PO_CC" -O2 -w $PO_BASE $INC "$HERE/vcposture_test.c" $PO_SRC -o /tmp/po_B 2>>/tmp/po.log \
   && "$PO_CC" -O2 -w $PO_BASE -DVP_NEGCTL $INC "$HERE/vcposture_test.c" $PO_SRC -o /tmp/po_C 2>>/tmp/po.log; then
	/tmp/po_A > /tmp/po_a.txt; /tmp/po_B > /tmp/po_b.txt; /tmp/po_C > /tmp/po_c.txt
	sed 's/^/    A: /' /tmp/po_a.txt; sed 's/^/    B: /' /tmp/po_b.txt
	ok=1
	grep -q '"keyslots":true' /tmp/po_a.txt && grep -q '"duress":true' /tmp/po_a.txt && grep -q '"hardware_factor":false' /tmp/po_a.txt && grep -q 'COUNT=2' /tmp/po_a.txt || ok=0
	grep -q '"keyslots":false' /tmp/po_b.txt && grep -q '"features_on":0' /tmp/po_b.txt && grep -q '"hardened":false' /tmp/po_b.txt || ok=0
	head -1 /tmp/po_b.txt | python3 -c 'import sys,json; json.loads(sys.stdin.readline())' 2>/dev/null || ok=0
	# negative control: the liar build (no features) must wrongly report keyslots:true
	if ! grep -q '"keyslots":true' /tmp/po_c.txt; then echo "    NEGCTL did not fire"; ok=0; fi
	if [ "$ok" = 1 ]; then
		echo "    MATCH: posture report tracks the compile guards (A on, B off, valid JSON); negctl liar detected"
	else
		echo "    POSTURE REPORT FAILED"; exit 1
	fi
else
	skip_step " no compiler for the posture report test (see /tmp/po.log)"
fi

echo ""
echo "[72] Offline verify without mounting: keyslot-area structural integrity (ROI item 16)"
# KeyslotStructuralCheck validates every occupied labeled slot's framing (version/kdf/cost/plen,
# record fits stride) WITHOUT the passphrase, over the real KeyslotStore. Clean area -> OK; corrupt a
# framing field -> flagged malformed (negative controls). Honest boundary: a flipped ciphertext byte
# is invisible to the structural check but the mount path (KeyslotOpen) still rejects it via the AEAD.
KV_CC=""
for c in clang gcc cc; do if command -v "$c" >/dev/null 2>&1; then KV_CC="$c"; break; fi; done
KV_WNO="-Wno-implicit-function-declaration -Wno-duplicate-decl-specifier"
KV_NOASM="-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3"
KV_DEF="-DVC_ENABLE_KEYSLOTS -DVC_ENABLE_VERIFY"
KV_INC="$INC -I$SRCROOT/Crypto"
if [ -n "$KV_CC" ] \
   && "$KV_CC" -O2 $KV_WNO $KV_NOASM $KV_DEF $KV_INC "$HERE/keyslot_verify_test.c" \
        "$SRCROOT/Common/KeyslotStore.c" "$SRCROOT/Common/Keyslot.c" "$SRCROOT/Common/AfSplit.c" \
        "$SRCROOT/Crypto/Sha2.c" "$SRCROOT/Crypto/chacha256.c" -o /tmp/keyslot_verify_test 2>/tmp/kv_log; then
	if /tmp/keyslot_verify_test > /tmp/kv_c.txt; then cat /tmp/kv_c.txt
		echo "    MATCH: offline verify accepts clean area, flags framing corruption; ct-tamper boundary documented"
	else cat /tmp/kv_c.txt; echo "    OFFLINE VERIFY FAILED"; exit 1; fi
else
	skip_step " no compiler for the offline verify test (see /tmp/kv_log)"
fi

echo ""
echo "[73] Reproducible build check (ROI item 39)"
# reproducible_build.sh compiles every fork Common module TWICE with normalized flags
# (SOURCE_DATE_EPOCH, -ffile-prefix-map, -g0) and requires byte-identical objects, scans the fork's
# own sources for __DATE__/__TIME__ constructs, and (negative control) shows an unnormalized build
# from a different path differs while -ffile-prefix-map makes it identical.
if "$HERE/reproducible_build.sh" | sed 's/^/    /'; then
	echo "    MATCH: fork objects build byte-identically; timestamp scan clean; normalization proven"
else
	echo "    REPRODUCIBLE BUILD CHECK FAILED"; exit 1
fi

echo ""
echo "[74] SBOM generation + coverage validation (ROI item 40)"
# sbom.py emits a CycloneDX 1.5 SBOM covering the fork's gated modules + external deps, then validates
# well-formedness and that EVERY fork module present in the tree is covered (so the SBOM can't drift).
# Negative control: an SBOM with a component removed must FAIL validation.
if python3 "$HERE/sbom.py" generate > /tmp/vc_sbom.json 2>/tmp/sbom_gen.log \
   && python3 -c 'import json,sys; d=json.load(open("/tmp/vc_sbom.json")); assert d["bomFormat"]=="CycloneDX"' 2>/dev/null \
   && python3 "$HERE/sbom.py" validate /tmp/vc_sbom.json > /tmp/sbom_val.txt 2>&1; then
	sed 's/^/    /' /tmp/sbom_val.txt
	python3 -c 'import json; d=json.load(open("/tmp/vc_sbom.json"));
comps=[c for c in d["components"] if c["name"]!="HeaderBackup"];
d["components"]=comps; json.dump(d, open("/tmp/vc_sbom_bad.json","w"))'
	if python3 "$HERE/sbom.py" validate --negctl /tmp/vc_sbom_bad.json > /tmp/sbom_nc.txt 2>&1; then
		sed 's/^/    /' /tmp/sbom_nc.txt
		echo "    MATCH: SBOM is well-formed + covers every fork module; a component-dropped SBOM is rejected"
	else
		sed 's/^/    /' /tmp/sbom_nc.txt; echo "    SBOM NEGATIVE CONTROL FAILED"; exit 1
	fi
else
	sed 's/^/    /' /tmp/sbom_val.txt 2>/dev/null; echo "    SBOM VALIDATION FAILED"; exit 1
fi
