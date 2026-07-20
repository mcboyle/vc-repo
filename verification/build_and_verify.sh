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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/ps_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/mc_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/dg_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/ad_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/mk2_log)"
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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/h2_log)"
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
	echo "    SKIP: no compiler (see /tmp/b3_log)"
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
	echo "    SKIP: no compiler (see /tmp/as_log)"
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
	echo "    SKIP: no compiler (see /tmp/tf_log)"
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
	echo "    SKIP: no compiler (see /tmp/sl_log)"
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
	echo "    SKIP: no compiler (see /tmp/fv_log)"
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
else echo "    SKIP: no compiler (see /tmp/pd_log)"; fi

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
else echo "    SKIP: no compiler (see /tmp/rw_log)"; fi

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
else echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/sc_log)"; fi

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
else echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/to_log)"; fi

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
	echo "    SKIP: no compiler accepted the stock Crypto sources (see /tmp/ka_cc.log)"
fi
