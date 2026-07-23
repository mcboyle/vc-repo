#!/usr/bin/env python3
"""
keyslot_reference.py — independent reference for the keyslot key-wrapping PoC.

Layer 1 of the two-way convention. PBKDF2-HMAC-SHA256 comes from hashlib (independent of VeraCrypt's
SHA-256); HMAC is the standard ipad/opad; ChaCha20 is reimplemented from the algorithm (20 rounds =
10 double-rounds), matching Crypto/chacha256.c's layout. build_and_verify.sh diffs the REF lines
against keyslot_poc.c, which drives the REAL compiled Sha2/chacha256 objects.
"""

import hashlib, hmac

M32 = (1 << 32) - 1
MK_LEN = 64
HDR_LEN = 8
ITERS = 4096
PW = b"slot-1 passphrase"
PW_WRONG = b"slot-1 passphras3"

# ---- ChaCha20 (20 rounds), identical layout to Crypto/chacha256.c ----
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

def chacha20(key32, iv8, data):
    inp = [0]*16
    inp[0], inp[1], inp[2], inp[3] = 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
    for i in range(8):
        inp[4 + i] = int.from_bytes(key32[i*4:i*4+4], "little")
    inp[12] = inp[13] = 0
    inp[14] = int.from_bytes(iv8[0:4], "little")
    inp[15] = int.from_bytes(iv8[4:8], "little")
    out = bytearray(); off = 0
    while off < len(data):
        blk = list(inp); chacha_core(blk, 10)
        ks = b"".join(((blk[i] + inp[i]) & M32).to_bytes(4, "little") for i in range(16))
        n = min(64, len(data) - off)
        out += bytes(data[off+i] ^ ks[i] for i in range(n))
        off += n
        inp[12] = (inp[12] + 1) & M32
        if inp[12] == 0:
            inp[13] = (inp[13] + 1) & M32
    return bytes(out)

def pbkdf2(pw, salt, iters, outlen):
    return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, outlen)

def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def keyslot_wrap(pw, salt, iters, mk):
    hdr = bytes([ord('V'), ord('C'), ord('K'), ord('S'), 1, 1, 0, 0])
    dk = pbkdf2(pw, salt, iters, 72)
    ct = chacha20(dk[0:32], dk[32:40], mk)
    tag = hmac_sha256(dk[40:72], hdr + ct)
    return hdr + ct + tag

def keyslot_unwrap(pw, salt, iters, rec):
    hdr = rec[0:HDR_LEN]; ct = rec[HDR_LEN:HDR_LEN+MK_LEN]; rtag = rec[HDR_LEN+MK_LEN:]
    dk = pbkdf2(pw, salt, iters, 72)
    if not hmac.compare_digest(hmac_sha256(dk[40:72], hdr + ct), rtag):
        return None
    return chacha20(dk[0:32], dk[32:40], ct)

def main():
    salt = bytes((i*11 + 5) & 0xff for i in range(16))
    mk = bytes((0x40 + i) & 0xff for i in range(MK_LEN))
    rec = keyslot_wrap(PW, salt, ITERS, mk)
    print("REF slot_record = " + rec.hex())
    print("REF roundtrip recovers master key = " + ("YES" if keyslot_unwrap(PW, salt, ITERS, rec) == mk else "NO"))
    print("REF wrong passphrase rejected = " + ("YES" if keyslot_unwrap(PW_WRONG, salt, ITERS, rec) is None else "NO"))

if __name__ == "__main__":
    main()
