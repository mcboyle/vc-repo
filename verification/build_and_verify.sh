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
