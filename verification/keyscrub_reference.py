#!/usr/bin/env python3
"""
keyscrub_reference.py — independent reimplementation of the KeyScrub RAM-encryption transform.

Layer 1 of the two-way verification convention: this file reimplements, from the algorithm alone,
the two primitives the transform is built from — t1ha2_atonce128 (128-bit Fast-Positive-Hash) and
ChaCha12 — and the VcKsRamTransform construction on top of them. build_and_verify.sh diffs the
"REF ..." lines printed here against the ones printed by keyscrub_selftest.c, which drives the REAL
compiled VeraCrypt objects. A byte-for-byte match proves the C integration computes exactly the
independently-specified math.

All words are little-endian, matching the C (t1ha2 fetch64_le and the x86_64/ARM64 targets).
"""

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

# ---- fixed vector, identical to keyscrub_selftest.c ----
AREA_LEN   = 256
SECRET_LEN = 32
HASH_MASK  = 0x0f1e2d3c4b5a6978
IV_MASK    = 0x8090a0b0c0d0e0f0
AREA_BASE  = 0x1122334455667788
ENC_ID     = 0x00000000deadbeef

def area_bytes():
    return bytes((i * 181 + 31) & 0xff for i in range(AREA_LEN))

def secret_bytes():
    return bytes((0x10 + i) & 0xff for i in range(SECRET_LEN))

# ================================================================= t1ha2 (128-bit)
PRIME = [0xEC99BF0D8372CAAB, 0x82434FE90EDCEF39, 0xD4F06DB99D67BE4B,
         0xBD9CACC22C6E9571, 0x9C06FAF4D023E3AB, 0xC060724A8424F345,
         0xCB5AF53AE3AAAC31]

def rot64(v, s):
    v &= M64
    return ((v >> s) | (v << (64 - s))) & M64

def mul128(a, b):
    full = (a & M64) * (b & M64)
    return (full & M64, (full >> 64) & M64)   # (low, high)

def mux64(v, prime):
    lo, hi = mul128(v, prime)
    return lo ^ hi

def mixup64(a, b, v, prime):
    lo, hi = mul128((b + v) & M64, prime)
    a ^= lo
    b = (b + hi) & M64
    return a & M64, b

def fetch64_le(data, off):
    return int.from_bytes(data[off:off + 8], "little")

def t1ha2_atonce128(data, length, seed):
    # init_ab / init_cd
    a = seed & M64
    b = length & M64
    x, y = seed & M64, length & M64
    c = (rot64(y, 23) + (~x & M64)) & M64
    d = ((~y & M64) + rot64(x, 19)) & M64

    assert length % 32 == 0, "reference vector uses a 32-byte-aligned area (tail case 0)"

    # T1HA2_LOOP: process 4x u64 per step while data < data+len-31
    off = 0
    if length > 32:
        detent = length - 31
        while True:
            w0 = fetch64_le(data, off + 0)
            w1 = fetch64_le(data, off + 8)
            w2 = fetch64_le(data, off + 16)
            w3 = fetch64_le(data, off + 24)
            d02 = (w0 + rot64((w2 + d) & M64, 56)) & M64
            c13 = (w1 + rot64((w3 + c) & M64, 19)) & M64
            d ^= (b + rot64(w1, 38)) & M64
            c ^= (a + rot64(w0, 57)) & M64
            b ^= (PRIME[6] * ((c13 + w2) & M64)) & M64
            a ^= (PRIME[5] * ((d02 + w3) & M64)) & M64
            d &= M64; c &= M64; b &= M64; a &= M64
            off += 32
            if not (off < detent):
                break
        length &= 31   # -> 0 for our vector

    # T1HA2_TAIL_ABCD, case 0 -> final128
    assert length == 0
    # final128(a,b,c,d)
    a, b = mixup64(a, b, rot64(c, 41) ^ d, PRIME[0])
    b, c = mixup64(b, c, rot64(d, 23) ^ a, PRIME[6])
    c, d = mixup64(c, d, rot64(a, 19) ^ b, PRIME[5])
    d, a = mixup64(d, a, rot64(b, 31) ^ c, PRIME[4])
    extra_high = (c + d) & M64
    return (a ^ b) & M64, extra_high   # (low result, extra_result)

# ================================================================= ChaCha (12-round)
def rotl32(x, n):
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32

def chacha_core(x, doublerounds):
    for _ in range(doublerounds):
        def qr(a, b, c, d):
            x[a] = (x[a] + x[b]) & M32; x[d] = rotl32(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & M32; x[b] = rotl32(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & M32; x[d] = rotl32(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & M32; x[b] = rotl32(x[b] ^ x[c], 7)
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)

def chacha_block(inp, doublerounds):
    x = list(inp)
    chacha_core(x, doublerounds)
    return [(x[i] + inp[i]) & M32 for i in range(16)]

def chacha12_encrypt(key32, iv8, data):
    inp = [0] * 16
    inp[0], inp[1], inp[2], inp[3] = 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
    for i in range(8):
        inp[4 + i] = int.from_bytes(key32[i * 4:i * 4 + 4], "little")
    inp[12] = 0
    inp[13] = 0
    inp[14] = int.from_bytes(iv8[0:4], "little")
    inp[15] = int.from_bytes(iv8[4:8], "little")
    out = bytearray()
    off = 0
    doublerounds = 12 // 2
    while off < len(data):
        blk = chacha_block(inp, doublerounds)
        ks = b"".join(w.to_bytes(4, "little") for w in blk)
        n = min(64, len(data) - off)
        out += bytes(data[off + i] ^ ks[i] for i in range(n))
        off += n
        inp[12] = (inp[12] + 1) & M32
        if inp[12] == 0:
            inp[13] = (inp[13] + 1) & M32
    return bytes(out)

# ================================================================= VcKsRamTransform
def ks_ram_transform(area, hash_mask, iv_mask, area_base, enc_id, buf):
    hash_seed = ((area_base + enc_id) & M64) ^ hash_mask
    lo, hi = t1ha2_atonce128(area, len(area), hash_seed)
    pbkey = [lo, hi, lo ^ hi, (lo + hi) & M64]
    key_bytes = b"".join(k.to_bytes(8, "little") for k in pbkey)
    # whiten the key with ChaCha12 keyed by itself, IV = hash_seed
    whitened = chacha12_encrypt(key_bytes, hash_seed.to_bytes(8, "little"), key_bytes)
    cipher_iv = ((area_base + enc_id) & M64) ^ iv_mask
    return chacha12_encrypt(whitened, cipher_iv.to_bytes(8, "little"), buf)

def main():
    area = area_bytes()
    secret = secret_bytes()
    protected = ks_ram_transform(area, HASH_MASK, IV_MASK, AREA_BASE, ENC_ID, secret)
    print("REF protected = " + protected.hex())
    roundtrip = ks_ram_transform(area, HASH_MASK, IV_MASK, AREA_BASE, ENC_ID, protected)
    print("REF roundtrip identity = " + ("YES" if roundtrip == secret else "NO"))
    print("REF protected != plaintext = " + ("YES" if protected != secret else "NO"))

if __name__ == "__main__":
    main()
