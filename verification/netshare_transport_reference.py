#!/usr/bin/env python3
"""
netshare_transport_reference.py — independent reference for netshare_transport_poc.c.

Layer 1 of the two-way convention: an independent Ed25519 group (python bigint, affine coordinates,
schoolbook) computes the enrolled McCallum-Relyea share for the transport PoC's exact seeds, so the
share the C PoC recovers over the socket is anchored byte-for-byte to a second implementation. The
group itself is additionally tied to RFC 8032 in netshare_ed25519_reference.py (step 39); here we only
reproduce the share value for the transport round-trip's seeds.

NOTE: the transport PoC clamps the RAW 32-byte seed (h[0]&=248; h[31]&=127|=64) rather than
SHA-512(seed) — the seeds are already uniform test vectors, and the MR algebra is independent of how
the scalars were produced. This reference matches that.
"""
import hashlib

p = 2**255 - 19
d = (-121665 * pow(121666, p - 2, p)) % p
By = (4 * pow(5, p - 2, p)) % p
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


def add(Pt, Q):
    x1, y1 = Pt
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % p
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % p
    return (x3, y3)


def mul(s, Pt):
    Q = (0, 1)
    while s:
        if s & 1:
            Q = add(Q, Pt)
        Pt = add(Pt, Pt)
        s >>= 1
    return Q


def compress(Pt):
    x, y = Pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def clamp_raw(seed):
    h = bytearray(seed)
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(bytes(h), "little")


def share_of(K):
    return hashlib.sha256(compress(K)).digest()


def main():
    sseed = bytes((0x11 * i + 3) & 0xFF for i in range(32))
    cseed = bytes((0x07 * i + 9) & 0xFF for i in range(32))
    s = clamp_raw(sseed)
    c = clamp_raw(cseed)
    S = mul(s, G)                 # server public
    share = share_of(mul(c, S))   # enrolled share = SHA-256(compress(c*S))
    print("REF enrolled share = " + share.hex())


if __name__ == "__main__":
    main()
