#!/usr/bin/env python3
# Independent HCTR2 reference (docs/HCTR2-SPEC.md, IDEAS-BACKLOG.md B).
# HCTR2 (Crowley, Huckleberry, Biggers — eprint 2021/1441; shipped in the Linux
# kernel) is the wide-block sibling of Adiantum tuned for AES-NI hardware:
# a tweakable super-pseudorandom permutation over the whole sector built from
# AES-256 (XCTR mode) + POLYVAL (RFC 8452). Any single-bit change randomizes
# the entire sector in both directions — the XTS-malleability kill for desktops.
#
#   hbar = E_K(le128(0));  L = E_K(le128(1))
#   H(T, M) = POLYVAL(hbar,  le128(2*bitlen(T) + 2 + [16 does not divide |M|])
#                            || zeropad16(T)
#                            || (M if 16 | |M| else zeropad16(M || 0x01)) )
#   Encrypt: M,N = P[:16], P[16:];  MM = M xor H(T,N);  UU = E_K(MM)
#            S = MM xor UU xor L;   V = N xor XCTR_K(S, |N|)
#            U = UU xor H(T,V);     C = U || V
#   XCTR_K(S) block i (from 1) = E_K(S xor le128(i))
#
# Verified against the 35 official google/hctr2 vectors (hctr2_kats.py) and,
# byte-for-byte, against hctr2_poc.c which drives the real in-tree AES objects.
# POLYVAL here is implemented from RFC 8452 directly and checked against the
# RFC's published example. AES-256 is reused from adiantum_reference (pure
# python, FIPS-197-anchored). Stdlib only.
import sys
from adiantum_kats import KATS as _AK  # noqa: F401  (same-dir import convention)
from adiantum_reference import aes256_encrypt_block, aes256_decrypt_block
import hctr2_kats

# ---- POLYVAL (RFC 8452): GF(2^128), P = x^128 + x^127 + x^126 + x^121 + 1,
# little-endian bit order (bit i of LE128(bytes) = coefficient of x^i).
_P = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1

def _dot(a, b):
    # a * b * x^-128 mod P   (the POLYVAL "dot" operation)
    c = 0
    for i in range(128):
        if (a >> i) & 1:
            c ^= b << i
    for _ in range(128):            # multiply by x^-128: 128 exact halvings
        if c & 1:
            c ^= _P
        c >>= 1
    return c

def polyval(h_bytes, blocks):
    h = int.from_bytes(h_bytes, 'little')
    s = 0
    for i in range(0, len(blocks), 16):
        x = int.from_bytes(blocks[i:i+16], 'little')
        s = _dot(s ^ x, h)
    return s.to_bytes(16, 'little')

def _rfc8452_kat():
    h = bytes.fromhex("25629347589242761d31f826ba4b757b")
    x = bytes.fromhex("4f4f95668c83dfb6401762bb2d01a262"
                      "d1a24ddd2721d006bbe45f20d3c9f362")
    return polyval(h, x).hex()   # want f7a3b47b846119fae5b7866cf5e5b77e

# ---- HCTR2 ----
def _pad16(b):
    return b + b'\0' * (-len(b) % 16)

def _hash(hbar, tweak, msg):
    rem = 1 if len(msg) % 16 else 0
    blocks = (8 * len(tweak) * 2 + 2 + rem).to_bytes(16, 'little')
    blocks += _pad16(tweak)
    blocks += msg if not rem else _pad16(msg + b'\x01')
    return polyval(hbar, blocks)

def _xctr(key, s, n):
    out = b''
    i = 1
    si = int.from_bytes(s, 'little')
    while len(out) < n:
        out += aes256_encrypt_block(key, (si ^ i).to_bytes(16, 'little'))
        i += 1
    return out[:n]

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def _setup(key):
    hbar = aes256_encrypt_block(key, bytes(16))
    L = aes256_encrypt_block(key, (1).to_bytes(16, 'little'))
    return hbar, L

def hctr2_encrypt(key, tweak, pt):
    assert len(pt) >= 16
    hbar, L = _setup(key)
    m, n = pt[:16], pt[16:]
    mm = _xor(m, _hash(hbar, tweak, n))
    uu = aes256_encrypt_block(key, mm)
    s = _xor(_xor(mm, uu), L)
    v = _xor(n, _xctr(key, s, len(n)))
    u = _xor(uu, _hash(hbar, tweak, v))
    return u + v

def hctr2_decrypt(key, tweak, ct):
    assert len(ct) >= 16
    hbar, L = _setup(key)
    u, v = ct[:16], ct[16:]
    uu = _xor(u, _hash(hbar, tweak, v))
    mm = aes256_decrypt_block(key, uu)
    s = _xor(_xor(mm, uu), L)
    n = _xor(v, _xctr(key, s, len(v)))
    m = _xor(mm, _hash(hbar, tweak, n))
    return m + n

def _hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

if __name__ == "__main__":
    ok = True

    # anchors: FIPS-197 AES and the RFC 8452 POLYVAL example
    aes_kat = aes256_encrypt_block(bytes(range(32)),
                                   bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
    print("REF aes256_fips197 " + aes_kat)
    print("REF polyval_rfc8452 " + _rfc8452_kat())

    kats = [(bytes.fromhex(k), bytes.fromhex(t), bytes.fromhex(p), bytes.fromhex(c))
            for (k, t, p, c) in hctr2_kats.KATS]
    all_match = True
    for i, (k, t, p, c) in enumerate(kats):
        got = hctr2_encrypt(k, t, p)
        print("REF kat_%d %s" % (i, got.hex()))
        all_match = all_match and (got == c)
    print("REF kat_all_match " + ("YES" if all_match else "NO"))
    ok = ok and all_match

    rt = all(hctr2_decrypt(k, t, c) == p for (k, t, p, c) in kats)
    print("REF roundtrip_all " + ("YES" if rt else "NO"))
    ok = ok and rt

    k, t, p, c = kats[hctr2_kats.DIFFUSION_IDX]
    bits = 8 * len(p)
    p2 = bytes([p[0] ^ 1]) + p[1:]
    c2 = hctr2_encrypt(k, t, p2)
    encd = _hamming(c, c2) >= 0.4 * bits and c2[:16] != c[:16] and c2[-16:] != c[-16:]
    print("REF enc_diffusion " + ("YES" if encd else "NO"))
    ct2 = bytes([c[0] ^ 1]) + c[1:]
    pd = hctr2_decrypt(k, t, ct2)
    decd = _hamming(p, pd) >= 0.4 * bits and pd[-16:] != p[-16:]
    print("REF dec_diffusion " + ("YES" if decd else "NO"))
    wk = bytes([k[0] ^ 1]) + k[1:]
    print("REF wrongkey " + ("YES" if hctr2_encrypt(wk, t, p) != c else "NO"))
    wt = bytes([t[0] ^ 1]) + t[1:]
    print("REF wrongtweak " + ("YES" if hctr2_encrypt(k, wt, p) != c else "NO"))
    ok = ok and encd and decd

    sys.exit(0 if ok else 1)
