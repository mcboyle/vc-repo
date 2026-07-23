#!/usr/bin/env python3
"""
sharecode_reference.py — independent reference for the bech32 share encoding (step [42]).

Layer 1 of the two-way convention, diffed against sharecode_test.c (which drives the REAL compiled
ShareCode.c + Shamir.c). bech32 (BIP-173) is reimplemented here from the spec; the GF(2^8) Shamir
split is reimplemented (independent of Shamir.c), so the encoded strings are recomputed end to end.
Payload = ver(1) || x || len || y[0..len)  (no MAC in the deterministic REF set; the MAC case is a
behavioural round-trip check on the C side).
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
HRP = "vcs"
VERSION = 1


# ---- GF(2^8) Shamir split (AES field 0x11B), matching Shamir.c ----
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
    acc = 0
    for c in reversed(coef):
        acc = gf_mul(acc, x) ^ c
    return acc


def shamir_split(secret, threshold, n_shares, rnd):
    shares = [{"x": s + 1, "y": bytearray(len(secret)), "len": len(secret)} for s in range(n_shares)]
    for b in range(len(secret)):
        coef = [secret[b]] + [rnd[(k - 1) * len(secret) + b] for k in range(1, threshold)]
        for s in range(n_shares):
            shares[s]["y"][b] = poly_eval(coef, shares[s]["x"])
    return shares


# ---- bech32 (BIP-173) ----
def polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def to5(data):
    acc = 0
    bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def encode(payload):
    data = to5(payload)
    values = hrp_expand(HRP) + data + [0] * 6
    pm = polymod(values) ^ 1
    checksum = [(pm >> (5 * (5 - i))) & 31 for i in range(6)]
    return HRP + "1" + "".join(CHARSET[d] for d in data + checksum)


def share_payload(share):
    return bytes([VERSION, share["x"], share["len"]]) + bytes(share["y"][: share["len"]])


def main():
    secret = bytes((0x40 + i) & 0xFF for i in range(32))
    rnd = bytes((i * 7 + 1) & 0xFF for i in range(2 * 32))
    shares = shamir_split(secret, 3, 5, rnd)
    for i, sh in enumerate(shares):
        print("REF share%d code = %s" % (i + 1, encode(share_payload(sh))))
    # share1 with the MAC appended (0xB0..0xCF)
    mac = bytes((0xB0 + i) & 0xFF for i in range(32))
    print("REF share1 code+mac = %s" % encode(share_payload(shares[0]) + mac))


if __name__ == "__main__":
    main()
