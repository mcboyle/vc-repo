#!/usr/bin/env python3
"""
voprf_ristretto_reference.py — independent reference for the verifiable OPRF / DLEQ proof (step [47]).

Layer 1 of the two-way convention, diffed against voprf_ristretto_poc.c. Reuses the (independent,
RFC-9496-anchored) ristretto255 group from oprf_ristretto_reference.py and adds the Chaum-Pedersen /
DLEQ proof: a1=rr*G, a2=rr*BE, c=challenge, s=rr-c*k mod L; verify recomputes a1=s*G+c*pk,
a2=s*BE+c*EE and checks the challenge. Scalars/nonce/input match the C PoC exactly.
"""

import hashlib
from oprf_ristretto_reference import (
    p, L, B, ext, add, scalarmult, ristretto_encode, hash_to_group, limbs,
)

Gbase = B


def sc(x):
    return x % L


def challenge(g, pk, be, ee, a1, a2):
    h = hashlib.sha512(b"VOPRF-DLEQ" + g + pk + be + ee + a1 + a2).digest()
    return int.from_bytes(h, "little") % L


def prove(k, rr, G, pk, BE, EE):
    a1 = scalarmult(rr, G)
    a2 = scalarmult(rr, BE)
    c = challenge(ristretto_encode(G), ristretto_encode(pk), ristretto_encode(BE),
                  ristretto_encode(EE), ristretto_encode(a1), ristretto_encode(a2))
    s = (rr - c * k) % L
    return c, s


def verify(G, pk, BE, EE, c, s):
    a1 = add(scalarmult(s, G), scalarmult(c, pk))
    a2 = add(scalarmult(s, BE), scalarmult(c, EE))
    cc = challenge(ristretto_encode(G), ristretto_encode(pk), ristretto_encode(BE),
                   ristretto_encode(EE), ristretto_encode(a1), ristretto_encode(a2))
    return cc == c


def le32(x):
    return x.to_bytes(32, "little")


def main():
    k = limbs([0x11223344556677, 0x8899001122334455, 0x6677889900112233, 0x0ABBCCDD12345678])
    r = limbs([0x0011223344556677, 0x8899AABBCCDDEEFF, 0x1122334455667788, 0x00FEDCBA98765432])
    rr = limbs([0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5A, 0x0102030405060708, 0x00C0FFEEC0FFEE00])
    inp = b"test input"

    G = Gbase
    pk = scalarmult(k, G)
    Pin = hash_to_group(inp)
    BE = scalarmult(r, Pin)
    EE = scalarmult(k, BE)
    c, s = prove(k, rr, G, pk, BE, EE)

    print("REF voprf pk = " + ristretto_encode(pk).hex())
    print("REF voprf proof_c = " + le32(c).hex())
    print("REF voprf proof_s = " + le32(s).hex())


if __name__ == "__main__":
    main()
