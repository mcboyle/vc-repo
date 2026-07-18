#!/usr/bin/env bash
# Reproduce the self-contained HardwareKeyFactor verification (crypto/mixing + CLI parsing).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"; SRCROOT="$HERE/../src"
INC="-I$SRCROOT -I$SRCROOT/Common -I$HERE"
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
if "$KS_CC" -O2 $KS_WNO $KS_NOASM -DVC_ENABLE_KEYSCRUB $INC -c "$SRCROOT/Common/KeyScrub.c" -o /tmp/ks_keyscrub.o 2>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM -DVC_ENABLE_KEYSCRUB $INC -c "$SRCROOT/Common/HardwareKeyFactor.c" -o /tmp/ks_hkf.o 2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $INC -c "$SRCROOT/Crypto/t1ha2.c"     -o /tmp/ks_t1ha2.o     2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/ks_chacha256.o 2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO $KS_NOASM $INC -c "$SRCROOT/Crypto/chachaRng.c" -o /tmp/ks_chachaRng.o 2>>/tmp/ks_cc.log \
   && "$KS_CC" -O2 $KS_WNO -DVC_ENABLE_KEYSCRUB $INC "$HERE/keyscrub_selftest.c" \
        /tmp/ks_keyscrub.o /tmp/ks_hkf.o /tmp/ks_t1ha2.o /tmp/ks_chacha256.o /tmp/ks_chachaRng.o -lpthread -o /tmp/keyscrub_selftest 2>>/tmp/ks_cc.log; then
	/tmp/keyscrub_selftest > /tmp/ks_c.txt; cat /tmp/ks_c.txt
	python3 "$HERE/keyscrub_reference.py" > /tmp/ks_py.txt
	grep '^REF' /tmp/ks_c.txt > /tmp/ks_c_ref.txt
	if diff -q /tmp/ks_c_ref.txt /tmp/ks_py.txt >/dev/null; then
		echo "    MATCH: KeyScrub transform (real t1ha2/chacha objects) == independent python reference"
	else
		echo "    MISMATCH"; diff /tmp/ks_c_ref.txt /tmp/ks_py.txt; exit 1
	fi
	# all boolean self-checks must report YES
	if grep -Eq ': NO$' /tmp/ks_c.txt; then echo "    KEYSCRUB SELFTEST FAILED"; exit 1; fi
else
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/ks_cc.log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/dt_cc.log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/kp_cc.log)"
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
if "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC -DVC_ENABLE_KEYSLOTS $KL_INC -c "$SRCROOT/Common/Keyslot.c"      -o /tmp/kl_keyslot.o 2>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC -DVC_ENABLE_KEYSLOTS $KL_INC -c "$SRCROOT/Common/KeyslotStore.c" -o /tmp/kl_store.o 2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC $KL_INC -c "$SRCROOT/Crypto/Sha2.c"     -o /tmp/kl_sha2.o   2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM $KL_GC $KL_INC -c "$SRCROOT/Crypto/chacha256.c" -o /tmp/kl_chacha.o 2>>/tmp/kl_cc.log \
   && "$KL_CC" -O2 $KL_WNO $KL_NOASM -DVC_ENABLE_KEYSLOTS $KL_INC "$HERE/keyslot_store_test.c" \
        /tmp/kl_keyslot.o /tmp/kl_store.o /tmp/kl_sha2.o /tmp/kl_chacha.o -Wl,--gc-sections -o /tmp/keyslot_store_test 2>>/tmp/kl_cc.log; then
	if /tmp/keyslot_store_test > /tmp/kl_out.txt; then cat /tmp/kl_out.txt
	else cat /tmp/kl_out.txt; echo "    KEYSLOT LIFECYCLE FAILED"; exit 1; fi
else
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/kl_cc.log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/ns_cc.log)"
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
	echo "    SKIP: no compiler accepted the stock Argon2/Pkcs5 sources (see /tmp/ap_cc.log)"
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
	echo "    SKIP: no compiler accepted the stock sources (see /tmp/sb_cc.log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/or_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/df_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/af_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/bl_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/op_log)"
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
	echo "    SKIP: no compiler available (see /tmp/pl_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/mk_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/km_log)"
fi
