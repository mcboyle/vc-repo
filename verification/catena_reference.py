#!/usr/bin/env python3
"""
catena_reference.py — independent reference for the Catena-BRG-style memory-hard KDF (step [48]).

Layer 1 of the two-way convention, diffed against catena_poc.c (which drives the REAL in-tree
Crypto/Sha2.c). This is the bit-reversal-graph (BRG) memory-hard core in the Catena style
(Forler-Lucks-Wenzel), over SHA-256: a sequential fill of 2^g blocks, then `lambda` BRG passes whose
bit-reversal permutation forces whole-array access. It is the memory-hard *core*, not the full Catena
KDF (no keyed tweak / client-independent-update wrapper) — a survey entry to sit beside Balloon and
scrypt, proven two-way. hashlib here; the C drives the real Sha2.c.
"""

import hashlib
import struct

DIGEST = 32


def le64(x):
    return struct.pack("<Q", x)


def H(*parts):
    c = hashlib.sha256()
    for pt in parts:
        c.update(pt)
    return c.digest()


def brg(i, g):
    """bit-reversal of i as a g-bit number."""
    r = 0
    for _ in range(g):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


def catena_brg(pwd, salt, g, lam):
    n = 1 << g
    v = [b""] * n
    v[0] = H(le64(0), pwd, salt)
    for i in range(1, n):
        v[i] = H(le64(i), v[i - 1])
    for _ in range(lam):
        r = [b""] * n
        r[0] = H(v[n - 1], v[brg(0, g)])
        for i in range(1, n):
            r[i] = H(r[i - 1], v[brg(i, g)])
        v = r
    return v[n - 1]


def main():
    pw = b"correct horse battery staple"
    salt = bytes((i * 5 + 1) & 0xFF for i in range(16))
    print("REF catena(g=8,lam=3) = " + catena_brg(pw, salt, 8, 3).hex())
    print("REF catena(g=8,lam=1) = " + catena_brg(pw, salt, 8, 1).hex())
    print("REF catena(g=10,lam=3) = " + catena_brg(pw, salt, 10, 3).hex())


if __name__ == "__main__":
    main()
