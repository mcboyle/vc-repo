#!/usr/bin/env python3
"""hkf_lencond_reference.py — independent reference for HKF response length conditioning
(CRC-seam addendum §6).

Two independent checks, emitted for the C harness to diff against:
  1. the conditioning rule — a RAW_SECRET response longer than 32 bytes becomes sha256(secret) (32
     bytes); a response <= 32 bytes is unchanged. Expected outputs are printed as EXP lines.
  2. the wrap boundary (§2) — replaying the pool write schedule (4 pool bytes per input byte into a
     128-byte pool), the max writes to any pool position is 1 for L<=32 and 2 for 33<=L<=64. Printed
     as WRAPEXP lines.

The secret of length L is the deterministic pattern (i*7+1)&0xff — identical to the C harness.
"""
import sys, hashlib

LENS = [20, 32, 33, 48, 64]
POOL = 128

def secret(L):
    return bytes((i * 7 + 1) & 0xff for i in range(L))

def conditioned(L):
    s = secret(L)
    return hashlib.sha256(s).digest() if L > 32 else s

def max_writes(L):
    counts = [0] * POOL
    wp = 0
    for _ in range(L):
        for _ in range(4):
            counts[wp] += 1
            wp += 1
            if wp >= POOL:
                wp = 0
    return max(counts)

def main():
    for L in LENS:
        c = conditioned(L)
        print("EXP", L, len(c), c.hex())
        print("WRAPEXP", L, max_writes(L))
    # the conditioned length for any >32 input is 32, which never wraps
    print("WRAPEXP", 32, max_writes(32))
    return 0

if __name__ == "__main__":
    sys.exit(main())
