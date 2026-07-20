#!/usr/bin/env python3
"""
oprf_ristretto_reference.py — independent reference for the ristretto255 DH-OPRF (step [43]).

Layer 1 of the two-way convention, diffed against oprf_ristretto_poc.c (which drives the REAL in-tree
Sha2.c and a from-scratch extended-coordinate group). Here ristretto255 (RFC 9496) + Elligator2 +
expand_message_xmd(SHA-512) (RFC 9380) + the OPRF protocol (RFC 9497 base mode) are implemented from
the specs using Python bigint and hashlib — independent of the C field/group code. The scalars and
input match oprf_ristretto_poc.c exactly.
"""

import hashlib

p = 2**255 - 19
d = (-121665 * pow(121666, p - 2, p)) % p
a = p - 1
L = 2**252 + 27742317777372353535851937790883648493


def inv(x):
    return pow(x, p - 2, p)


SQRT_M1 = pow(2, (p - 1) // 4, p)


def sqrt_ratio_i(u, v):
    u %= p
    v %= p
    v3 = (v * v % p) * v % p
    v7 = (v3 * v3 % p) * v % p
    r = (u * v3) % p * pow((u * v7) % p, (p - 5) // 8, p) % p
    check = (v * r % p) * r % p
    correct = (check == u)
    flipped = (check == (-u) % p)
    flipped_i = (check == ((-u) * SQRT_M1) % p)
    if flipped or flipped_i:
        r = (SQRT_M1 * r) % p
    if r % 2 == 1:
        r = (-r) % p
    return (correct or flipped), r


_, INVSQRT_A_MINUS_D = sqrt_ratio_i(1, (a - d) % p)
_, SQRT_AD_MINUS_ONE = sqrt_ratio_i((a * d - 1) % p, 1)
ONE_MINUS_D_SQ = (1 - d * d) % p
D_MINUS_ONE_SQ = ((d - 1) * (d - 1)) % p

By = (4 * inv(5)) % p
_u = (By * By - 1) % p
_v = (d * By * By + 1) % p
Bx = pow(_u * inv(_v) % p, (p + 3) // 8, p)
if (Bx * Bx - _u * inv(_v)) % p != 0:
    Bx = (Bx * SQRT_M1) % p
if Bx % 2 != 0:
    Bx = p - Bx


def ext(x, y):
    return (x, y, 1, (x * y) % p)


B = ext(Bx, By)


def add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A_ = (Y1 - X1) * (Y2 - X2) % p
    Bb = (Y1 + X1) * (Y2 + X2) % p
    C_ = T1 * (2 * d % p) % p * T2 % p
    Dd = 2 * Z1 % p * Z2 % p
    E = (Bb - A_) % p
    F = (Dd - C_) % p
    G = (Dd + C_) % p
    H = (Bb + A_) % p
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def scalarmult(k, P):
    Q = ext(0, 1)
    for i in range(255, -1, -1):
        Q = add(Q, Q)
        if (k >> i) & 1:
            Q = add(Q, P)
    return Q


def is_neg(x):
    return (x % p) & 1


def ct_abs(x):
    x %= p
    return (p - x) if (x & 1) else x


def ristretto_encode(P):
    X, Y, Z, T = P
    u1 = (Z + Y) % p * ((Z - Y) % p) % p
    u2 = X * Y % p
    _, invsqrt = sqrt_ratio_i(1, (u1 * (u2 * u2 % p)) % p)
    D1 = invsqrt * u1 % p
    D2 = invsqrt * u2 % p
    Zinv = D1 * D2 % p * T % p
    ix0 = X * SQRT_M1 % p
    iy0 = Y * SQRT_M1 % p
    ench = D1 * INVSQRT_A_MINUS_D % p
    rotate = is_neg(T * Zinv % p)
    Xn = iy0 if rotate else X
    Yn = ix0 if rotate else Y
    Dn = ench if rotate else D2
    if is_neg(Xn * Zinv % p):
        Yn = (-Yn) % p
    s = (Dn * ((Z - Yn) % p)) % p
    if is_neg(s):
        s = (-s) % p
    return s.to_bytes(32, "little")


def MAP(t):
    r = SQRT_M1 * t % p * t % p
    u = (r + 1) * ONE_MINUS_D_SQ % p
    v = ((p - 1) - r * d) % p * ((r + d) % p) % p
    was_sq, s = sqrt_ratio_i(u, v)
    s_prime = (p - ct_abs(s * t % p)) % p
    s = s if was_sq else s_prime
    c = (p - 1) if was_sq else r
    N = (c * ((r - 1) % p) % p * D_MINUS_ONE_SQ % p - v) % p
    w0 = 2 * s % p * v % p
    w1 = N * SQRT_AD_MINUS_ONE % p
    w2 = (1 - s * s) % p
    w3 = (1 + s * s) % p
    return (w0 * w3 % p, w2 * w1 % p, w1 * w3 % p, w0 * w2 % p)


def expand_message_xmd(msg, DST, length):
    DST_prime = DST + bytes([len(DST)])
    msg_prime = b"\x00" * 128 + msg + length.to_bytes(2, "big") + b"\x00" + DST_prime
    b0 = hashlib.sha512(msg_prime).digest()
    b1 = hashlib.sha512(b0 + b"\x01" + DST_prime).digest()
    return b1[:length]


CONTEXT = b"OPRFV1-" + bytes([0x00]) + b"-" + b"ristretto255-SHA512"


def hash_to_group(msg):
    uni = expand_message_xmd(msg, b"HashToGroup-" + CONTEXT, 64)
    r1 = int.from_bytes(uni[0:32], "little") % p
    r2 = int.from_bytes(uni[32:64], "little") % p
    return add(MAP(r1), MAP(r2))


def finalize(inp, enc):
    return hashlib.sha512(len(inp).to_bytes(2, "big") + inp + len(enc).to_bytes(2, "big") + enc + b"Finalize").digest()


def limbs(v):
    return v[0] | (v[1] << 64) | (v[2] << 128) | (v[3] << 192)


def ph(label, b):
    print(label + b.hex())


def main():
    # (1) RFC 9496 A.1 basepoint-multiples KAT
    acc = ext(0, 1)
    for i in range(1, 6):
        acc = add(acc, B)
        print("REF ristretto %dB = %s" % (i, ristretto_encode(acc).hex()))

    # (2) DH-OPRF over ristretto255 — scalars/input identical to oprf_ristretto_poc.c
    k = limbs([0x11223344556677, 0x8899001122334455, 0x6677889900112233, 0x0ABBCCDD12345678])
    r = limbs([0x0011223344556677, 0x8899AABBCCDDEEFF, 0x1122334455667788, 0x00FEDCBA98765432])
    inp = b"test input"

    Pin = hash_to_group(inp)
    BE = scalarmult(r, Pin)
    EE = scalarmult(k, BE)
    N = scalarmult(pow(r, L - 2, L), EE)
    ph("REF oprf blinded = ", ristretto_encode(BE))
    ph("REF oprf evaluated = ", ristretto_encode(EE))
    ph("REF oprf output = ", finalize(inp, ristretto_encode(N)))


if __name__ == "__main__":
    main()
