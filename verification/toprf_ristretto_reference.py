#!/usr/bin/env python3
"""
toprf_ristretto_reference.py — independent reference for the threshold OPRF over ristretto255 (step [44]).

Layer 1 of the two-way convention, diffed against toprf_ristretto_poc.c. The ristretto255 group +
OPRF are reused from oprf_ristretto_reference.py (itself independent of the C, and anchored to the
RFC 9496 KAT); this file adds the Shamir split of the server key over the scalar field Z_L and the
Lagrange-in-the-exponent combine. Scalars/coefficients/input match the C PoC exactly.
"""

from oprf_ristretto_reference import (
    p, L, B, ext, add, scalarmult, ristretto_encode, hash_to_group, finalize, limbs,
)


def sinv(x):
    return pow(x, L - 2, L)


def share(k, coef, t, x):
    acc = k
    xi = 1
    for j in range(1, t):
        xi = xi * x % L
        acc = (acc + coef[j - 1] * xi) % L
    return acc


def lagrange0(xs, i):
    num = 1
    den = 1
    xi = xs[i]
    for j in range(len(xs)):
        if j == i:
            continue
        num = num * xs[j] % L
        den = den * ((xs[j] - xi) % L) % L
    return num * sinv(den) % L


def combine(xs, Z):
    acc = ext(0, 1)
    for i in range(len(xs)):
        acc = add(acc, scalarmult(lagrange0(xs, i), Z[i]))
    return acc


def main():
    # RFC 9496 KAT lines (so the diff includes the group anchor, matching the C REF set is not needed
    # here — the C prints only threshold REFs; keep this reference's REFs to the threshold outputs)
    k = limbs([0x11223344556677, 0x8899001122334455, 0x6677889900112233, 0x0ABBCCDD12345678])
    a1 = limbs([0x0102030405060708, 0x1112131415161718, 0x2122232425262728, 0x0132333435363738])
    a2 = limbs([0x5152535455565758, 0x6162636465666768, 0x7172737475767778, 0x0182838485868788])
    r = limbs([0x0011223344556677, 0x8899AABBCCDDEEFF, 0x1122334455667788, 0x00FEDCBA98765432])
    coef = [a1, a2]
    T, Nn = 3, 5
    inp = b"test input"

    Pin = hash_to_group(inp)
    BE = scalarmult(r, Pin)
    ki_BE = []
    for s in range(Nn):
        ks = share(k, coef, T, s + 1)
        ki_BE.append(scalarmult(ks, BE))

    rinv = sinv(r)
    Npt = combine([1, 2, 3], [ki_BE[0], ki_BE[1], ki_BE[2]])
    Npt = scalarmult(rinv, Npt)
    nEnc = ristretto_encode(Npt)
    print("REF toprf output = " + finalize(inp, nEnc).hex())
    print("REF toprf combined element = " + nEnc.hex())


if __name__ == "__main__":
    main()
