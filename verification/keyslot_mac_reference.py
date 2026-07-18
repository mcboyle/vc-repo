#!/usr/bin/env python3
# Independent reference for the keyslot-area MAC (docs/KEYSLOT-MAC-SPEC.md,
# IDEAS-BACKLOG.md P0.5). Pure-python ChaCha20 (DJB 8-byte-nonce / 64-bit-counter
# variant, matching the in-tree Crypto/chacha256.c) for the one-time-key
# derivation, and a transparent big-integer Poly1305 for the tag. Independent of
# keyslot_mac_poc.c, which drives the real in-tree objects. REF lines are diffed
# byte-for-byte by build_and_verify.sh.
import struct, sys
from poly1305_reference import poly1305_mac  # the step-18 bigint Poly1305

def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl(s[b], 7)

def chacha20_block(key, counter, nonce8, rounds=20):
    # DJB layout: constants | key[8] | counter[2, 64-bit LE] | nonce[2, 64-bit LE]
    const = b"expand 32-byte k"
    st = list(struct.unpack("<4I", const))
    st += list(struct.unpack("<8I", key))
    st += [counter & 0xffffffff, (counter >> 32) & 0xffffffff]
    st += list(struct.unpack("<2I", nonce8))
    work = st[:]
    for _ in range(rounds // 2):
        _qr(work, 0, 4, 8, 12); _qr(work, 1, 5, 9, 13)
        _qr(work, 2, 6, 10, 14); _qr(work, 3, 7, 11, 15)
        _qr(work, 0, 5, 10, 15); _qr(work, 1, 6, 11, 12)
        _qr(work, 2, 7, 8, 13); _qr(work, 3, 4, 9, 14)
    out = [(work[i] + st[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)

def otk_from_chacha(mac_key, nonce8):
    return chacha20_block(mac_key, 0, nonce8, 20)[:32]

def keyslot_area_mac(mac_key, nonce8, area):
    return poly1305_mac(area, otk_from_chacha(mac_key, nonce8))

def ct_eq(a, b):
    return a == b   # reference need not be constant-time; the C side is

NSLOT, SLOTSZ = 4, 96
AREASZ = NSLOT * SLOTSZ

if __name__ == "__main__":
    mac_key = bytes((0xA0 + i) & 0xff for i in range(32))
    nonce = bytes((i * 9 + 1) & 0xff for i in range(8))
    area = bytes((i * 31 + 7) & 0xff for i in range(AREASZ))

    print("REF chacha_zero_kat " + chacha20_block(bytes(32), 0, bytes(8), 20)[:32].hex())

    tag = keyslot_area_mac(mac_key, nonce, area)
    print("REF mac " + tag.hex())
    print("REF accept_valid " + ("YES" if ct_eq(keyslot_area_mac(mac_key, nonce, area), tag) else "NO"))

    t = bytearray(area); t[123] ^= 0x08
    vt = keyslot_area_mac(mac_key, nonce, bytes(t))
    print("REF tamper_mac " + vt.hex())
    print("REF reject_tamper " + ("YES" if not ct_eq(vt, tag) else "NO"))

    vtr = keyslot_area_mac(mac_key, nonce, area[:AREASZ - SLOTSZ])
    print("REF trunc_mac " + vtr.hex())
    print("REF reject_trunc " + ("YES" if not ct_eq(vtr, tag) else "NO"))

    wk = bytearray(mac_key); wk[0] ^= 0x01
    print("REF reject_wrongkey " + ("YES" if not ct_eq(keyslot_area_mac(bytes(wk), nonce, area), tag) else "NO"))

    nn = bytearray(nonce); nn[7] ^= 0x01
    print("REF nonce_binds " + ("YES" if not ct_eq(keyslot_area_mac(mac_key, bytes(nn), area), tag) else "NO"))
