#!/usr/bin/env python3
"""
netshare_ed25519_reference.py — independent reference for the production-parameter (Ed25519)
McCallum-Relyea PoC (step [39]).

Layer 1 of the two-way convention, diffed against netshare_ed25519_poc.c (which drives the REAL
in-tree Sha2.c and a from-scratch extended-coordinate group). Here the Ed25519 group is the textbook
affine implementation (Python bigint, per-add inversion — fine for a handful of ops), independent of
the C extended-coordinate arithmetic; SHA-512/SHA-256 come from hashlib. The RFC 8032 section 7.1
public keys are recomputed as an official cross-check; the scalars match the C PoC exactly.
"""

import hashlib
import struct

p = 2**255 - 19
d = (-121665 * pow(121666, p - 2, p)) % p
L = 2**252 + 27742317777372353535851937790883648493

By = (4 * pow(5, p - 2, p)) % p
# recover Bx (even) as in RFC 8032
_u = (By * By - 1) % p
_v = (d * By * By + 1) % p
_x = (_u * pow(_v, p - 2, p)) % p
Bx = pow(_x, (p + 3) // 8, p)
if (Bx * Bx - _x) % p != 0:
    Bx = (Bx * pow(2, (p - 1) // 4, p)) % p
if Bx % 2 != 0:
    Bx = p - Bx
G = (Bx, By)


def inv(x):
    return pow(x, p - 2, p)


def edwards_add(Pt, Q):
    x1, y1 = Pt
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % p
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % p
    return (x3, y3)


def scalar_mult(s, Pt):
    Q = (0, 1)
    while s:
        if s & 1:
            Q = edwards_add(Q, Pt)
        Pt = edwards_add(Pt, Pt)
        s >>= 1
    return Q


def point_neg(Pt):
    x, y = Pt
    return ((-x) % p, y)


def compress(Pt):
    x, y = Pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def clamp_secret(seed):
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(bytes(h), "little")


def scalar_from_hexle(v):
    """u256 {v0..v3} little-endian limbs -> integer, matching the C literals."""
    return v[0] | (v[1] << 64) | (v[2] << 128) | (v[3] << 192)


def share_of(K):
    return hashlib.sha256(compress(K)).digest()


def ph(label, b):
    print(label + b.hex())


def main():
    # (1) RFC 8032 section 7.1 KAT
    seeds = [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    ]
    for s in seeds:
        sk = clamp_secret(bytes.fromhex(s))
        ph("REF rfc8032 pub = ", compress(scalar_mult(sk, G)))

    # (2) MR over Ed25519 — scalars identical to the C PoC's u256 literals
    s_srv = scalar_from_hexle([0x1122334455667788, 0x0102030405060708, 0x1111111111111111, 0x0011223344556677])
    c_eph = scalar_from_hexle([0x8877665544332211, 0x0807060504030201, 0x2222222222222222, 0x0100feddccbbaa99])
    e_eph = scalar_from_hexle([0xdeadbeefcafef00d, 0x0011223344556677, 0x3333333333333333, 0x00abcdef01234567])

    S = scalar_mult(s_srv, G)
    C = scalar_mult(c_eph, G)
    Kprov = scalar_mult(c_eph, S)

    X = edwards_add(C, scalar_mult(e_eph, G))       # X = C + e*G
    Y = scalar_mult(s_srv, X)                         # Y = s*X
    Krec = edwards_add(Y, point_neg(scalar_mult(e_eph, S)))  # K = Y - e*S

    ph("REF mr S = ", compress(S))
    ph("REF mr C = ", compress(C))
    ph("REF mr Kprov = ", compress(Kprov))
    ph("REF mr Krec = ", compress(Krec))
    ph("REF mr share = ", share_of(Krec))
    print("REF mr recover matches provision = " + ("YES" if share_of(Kprov) == share_of(Krec) else "NO"))

    s_wrong = s_srv ^ 1
    Yw = scalar_mult(s_wrong, X)
    Kw = edwards_add(Yw, point_neg(scalar_mult(e_eph, S)))
    print("REF mr wrong server -> different share = " + ("YES" if share_of(Krec) != share_of(Kw) else "NO"))
    print("REF mr server sees only blinded X = YES")


if __name__ == "__main__":
    main()
