#!/usr/bin/env python3
"""hkf_mixv2_reference.py — independent reference for the Rank-1 v2 mixing (CRC-seam addendum §7).

v2 replaces the CRC-32 keyfile-pool combine with HKDF-SHA256:
    OKM[128] = HKDF-SHA256(salt=<empty>, IKM = password || response, info = "VeraCrypt/HKF/mix/v2", L=128)
Reads 'PASSWORD <hex>' and 'RESPONSE <hex>' from stdin and prints the expected 128-byte mixed password
as 'MIXV2EXP <hex>'. The C harness prints what the real HKFMixResponseIntoPasswordV2 produced; the
suite diffs them byte-for-byte.
"""
import sys, hmac, hashlib

INFO = b"VeraCrypt/HKF/mix/v2"
L = 128
HASHLEN = 32

def hkdf(ikm, info=INFO, length=L, salt=b"\x00" * HASHLEN):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()       # Extract
    okm, t, i = b"", b"", 0
    while len(okm) < length:                                  # Expand
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def main():
    v = {}
    for line in sys.stdin:
        p = line.split()
        if len(p) == 2 and p[0] in ("PASSWORD", "RESPONSE"):
            v[p[0]] = bytes.fromhex(p[1])
    if not {"PASSWORD", "RESPONSE"} <= set(v):
        print("MISSING-INPUT"); return 1
    print("MIXV2EXP", hkdf(v["PASSWORD"] + v["RESPONSE"]).hex())
    return 0

if __name__ == "__main__":
    sys.exit(main())
