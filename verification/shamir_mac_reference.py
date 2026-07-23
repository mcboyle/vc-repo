#!/usr/bin/env python3
"""
shamir_mac_reference.py — independent reference for the keyed per-share MAC (step [40]).

Layer 1 of the two-way convention, diffed against shamir_mac_test.c (which drives the REAL compiled
Shamir.c + ShamirMac.c). GF(2^8) Shamir split is reimplemented here (AES field 0x11B), independent
of Shamir.c; HMAC-SHA256 comes from the stdlib. The per-share tag is
HMAC-SHA256(macKey, b"VCSMshare1" || x || len || y[0..len)), matching ShamirMac.c.
"""

import hmac
import hashlib

SEC_LEN = 32
THRESH = 3
NSH = 5
DOMAIN = b"VCSMshare1"


# ---- GF(2^8), AES reduction 0x11B (matches Shamir.c) ----
def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def poly_eval(coef, x):
    """Horner over GF(2^8): coef[0] + coef[1]x + ... (coef[0] = secret byte)."""
    acc = 0
    for c in reversed(coef):
        acc = gf_mul(acc, x) ^ c
    return acc


def shamir_split(secret, threshold, n_shares, rnd):
    """Mirror Shamir.c: coef[0]=secret byte, coef[1..t-1] from rnd; share x = 1..n."""
    shares = []
    for s in range(n_shares):
        shares.append({"x": s + 1, "y": bytearray(len(secret)), "len": len(secret)})
    for b in range(len(secret)):
        coef = [secret[b]]
        for k in range(1, threshold):
            coef.append(rnd[(k - 1) * len(secret) + b])
        for s in range(n_shares):
            shares[s]["y"][b] = poly_eval(coef, shares[s]["x"])
    return shares


def share_mac(mac_key, share):
    hdr = DOMAIN + bytes([share["x"], share["len"]])
    return hmac.new(mac_key, hdr + bytes(share["y"][: share["len"]]), hashlib.sha256).digest()


def main():
    secret = bytes((0x40 + i) & 0xFF for i in range(SEC_LEN))
    rnd = bytes((i * 7 + 1) & 0xFF for i in range((THRESH - 1) * SEC_LEN))
    mac_key = bytes((0x11 * (i + 1)) & 0xFF for i in range(32))

    shares = shamir_split(secret, THRESH, NSH, rnd)
    for i, sh in enumerate(shares):
        print("REF share%d tag = %s" % (i + 1, share_mac(mac_key, sh).hex()))


if __name__ == "__main__":
    main()
