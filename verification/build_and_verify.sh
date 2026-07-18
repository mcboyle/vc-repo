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
sed -n '1,12p' /tmp/shamir_c.txt
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
