#!/usr/bin/env python3
# Independent Threefish reference (docs/LARGE-BLOCK-SPEC.md, IDEAS-BACKLOG.md
# "Large-block ciphers" row). Threefish is the tweakable block cipher inside
# Skein; its 1024-bit block gives ~2^64x the birthday-bound headroom of AES's
# 128-bit block — relevant for very large volumes and wide-block constructions.
# This implements the compact canonical algorithm (Skein 1.3 spec) for both the
# 512-bit and 1024-bit block sizes.
#
# Threefish-512 is validated against the OFFICIAL Botan published vectors
# (threefish_kats.py, TF512) — the independent authority that pins down the
# MIX/rotation/key-schedule/permute machinery. Threefish-1024 is the identical
# construction with 16 words and its own rotation table + permutation; it is
# proven by byte-identical agreement with threefish_poc.c plus encrypt/decrypt
# round-trip. Stdlib only.
import sys
import threefish_kats

M64 = (1 << 64) - 1
C240 = 0x1BD11BDAA9FC1A22

ROT512 = [[46, 36, 19, 37], [33, 27, 14, 42], [17, 49, 36, 39], [44, 9, 54, 56],
          [39, 30, 34, 24], [13, 50, 10, 17], [25, 29, 39, 43], [8, 35, 56, 22]]
PERM512 = [2, 1, 4, 7, 6, 5, 0, 3]

ROT1024 = [[24, 13, 8, 47, 8, 17, 22, 37], [38, 19, 10, 55, 49, 18, 23, 52],
           [33, 4, 51, 13, 34, 41, 59, 17], [5, 20, 48, 41, 47, 28, 16, 25],
           [41, 9, 37, 31, 12, 47, 44, 30], [16, 34, 56, 51, 4, 53, 42, 41],
           [31, 44, 47, 46, 19, 42, 44, 25], [9, 48, 35, 52, 23, 31, 37, 20]]
PERM1024 = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1]

def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & M64

def _params(nw):
    if nw == 8:
        return ROT512, PERM512, 72
    return ROT1024, PERM1024, 80

def _key_schedule(key_words, tweak_words, nw):
    k = key_words[:] + [C240]
    for w in key_words:
        k[nw] ^= w
    t = [tweak_words[0], tweak_words[1], tweak_words[0] ^ tweak_words[1]]
    nrounds = 72 if nw == 8 else 80
    nsub = nrounds // 4 + 1
    ks = []
    for s in range(nsub):
        sub = [k[(s + i) % (nw + 1)] for i in range(nw)]
        sub[nw - 3] = (sub[nw - 3] + t[s % 3]) & M64
        sub[nw - 2] = (sub[nw - 2] + t[(s + 1) % 3]) & M64
        sub[nw - 1] = (sub[nw - 1] + s) & M64
        ks.append(sub)
    return ks

def encrypt_block(key_words, tweak_words, block_words):
    nw = len(block_words)
    rot, perm, nrounds = _params(nw)
    ks = _key_schedule(key_words, tweak_words, nw)
    v = block_words[:]
    for d in range(nrounds):
        if d % 4 == 0:
            v = [(v[i] + ks[d // 4][i]) & M64 for i in range(nw)]
        nv = v[:]
        for i in range(nw // 2):
            x0, x1 = v[2 * i], v[2 * i + 1]
            y0 = (x0 + x1) & M64
            y1 = _rotl(x1, rot[d % 8][i]) ^ y0
            nv[2 * i], nv[2 * i + 1] = y0, y1
        v = [nv[perm[i]] for i in range(nw)]
    return [(v[i] + ks[nrounds // 4][i]) & M64 for i in range(nw)]

def decrypt_block(key_words, tweak_words, block_words):
    nw = len(block_words)
    rot, perm, nrounds = _params(nw)
    ks = _key_schedule(key_words, tweak_words, nw)
    inv = [0] * nw
    for i in range(nw):
        inv[perm[i]] = i
    v = [(block_words[i] - ks[nrounds // 4][i]) & M64 for i in range(nw)]
    for d in range(nrounds - 1, -1, -1):
        pv = [v[inv[i]] for i in range(nw)]
        nv = pv[:]
        for i in range(nw // 2):
            y0, y1 = pv[2 * i], pv[2 * i + 1]
            x1 = _rotl(y1 ^ y0, 64 - rot[d % 8][i])
            x0 = (y0 - x1) & M64
            nv[2 * i], nv[2 * i + 1] = x0, x1
        v = nv
        if d % 4 == 0:
            v = [(v[i] - ks[d // 4][i]) & M64 for i in range(nw)]
    return v

def _tow(b):
    return [int.from_bytes(b[i:i+8], 'little') for i in range(0, len(b), 8)]
def _fromw(w):
    return b''.join(x.to_bytes(8, 'little') for x in w)

def encrypt(key, tweak, pt):
    return _fromw(encrypt_block(_tow(key), _tow(tweak), _tow(pt)))
def decrypt(key, tweak, ct):
    return _fromw(decrypt_block(_tow(key), _tow(tweak), _tow(ct)))

if __name__ == "__main__":
    ok = True
    # Threefish-512 against the official Botan vectors
    all512 = True
    for i, (k, t, p, c) in enumerate(threefish_kats.TF512):
        got = encrypt(bytes.fromhex(k), bytes.fromhex(t), bytes.fromhex(p)).hex()
        print("REF tf512_%d %s" % (i, got))
        all512 = all512 and got == c.lower()
    print("REF tf512_official_match " + ("YES" if all512 else "NO"))
    ok = ok and all512

    # Threefish-1024: deterministic key/tweak/plaintext; cross-checked C<->python
    key = bytes((i) & 0xff for i in range(128))
    tweak = bytes((0x10 + i) & 0xff for i in range(16))
    pt = bytes((0xff - i) & 0xff for i in range(128))
    ct = encrypt(key, tweak, pt)
    print("REF tf1024_ct " + ct.hex())
    rt = decrypt(key, tweak, ct) == pt
    print("REF tf1024_roundtrip " + ("YES" if rt else "NO"))
    # 512 round-trip too
    k, t, p, c = threefish_kats.TF512[0]
    rt5 = decrypt(bytes.fromhex(k), bytes.fromhex(t), bytes.fromhex(c)) == bytes.fromhex(p)
    print("REF tf512_roundtrip " + ("YES" if rt5 else "NO"))
    ok = ok and rt and rt5
    sys.exit(0 if ok else 1)
