#!/usr/bin/env python3
"""
keyslotaf_reference.py — independent reference for AF-split keyslot records (step [36]).

Layer 1 of the two-way convention, diffed against keyslotaf_test.c (which drives the REAL compiled
AfSplit.c + Keyslot.c + KeyslotStore.c). PBKDF2 comes from hashlib, HMAC from the stdlib, ChaCha20
is reimplemented from the algorithm (matching Crypto/chacha256.c's layout, as keyslot_reference.py
established), and the LUKS AF diffuse (with the trailing partial section) is reimplemented from the
spec (docs/AF-SPLIT-SPEC.md) — none of it derived from the C sources under test.

Record formats recomputed here (KeyslotStore.c):
  labeled v2: magic[4]="VCKS" ver[1]=2 kdf[1]=1 rsv[2]=s(LE) cost[4](LE) plen[2](LE) salt[32]
              ct[s*plen] tag[32] <random pad to 1024>
  bare:       salt[32] ct[s*plen] tag[32] <random pad to 1024>, aad = "VCKSbare"||salt
"""

import hashlib, hmac

M32 = (1 << 32) - 1
STRIDE = 1024
AREA_SLOTS = 8
VMK_LEN = 64
PLEN = VMK_LEN + 1
AF_S = 4
COST = 256
L_CT = 46
B_CT = 32

VMK = bytes((0x40 + i) & 0xFF for i in range(VMK_LEN))

# ---- deterministic rng (mirrors the harness LCG) ----
class Lcg:
    def __init__(self, seed):
        self.s = seed & M32
    def rand(self, n):
        out = bytearray()
        for _ in range(n):
            self.s = (self.s * 1664525 + 1013904223) & M32
            out.append((self.s >> 24) & 0xFF)
        return bytes(out)

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

def kdf(pw, salt, outlen=72, iters=COST):
    return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, outlen)

def hs256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

# ---- LUKS AF diffuse/split/merge (spec reimplementation, incl. trailing partial section) ----
def af_diffuse(src):
    n = len(src)
    out = bytearray()
    full, rem = divmod(n, 32)
    for i in range(full + (1 if rem else 0)):
        take = 32 if i < full else rem
        h = hashlib.sha256(i.to_bytes(4, "big") + src[i*32:i*32+take]).digest()
        out += h[:take]
    return bytes(out)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def af_split(material, s, rng):
    n = len(material)
    stripes = []
    buf = bytes(n)
    for _ in range(s - 1):
        st = rng.rand(n)
        stripes.append(st)
        buf = af_diffuse(xor(buf, st))
    stripes.append(xor(material, buf))
    return b"".join(stripes)

def af_merge(blob, n, s):
    buf = bytes(n)
    for i in range(s - 1):
        buf = af_diffuse(xor(buf, blob[i*n:(i+1)*n]))
    return xor(blob[(s-1)*n:s*n], buf)

# ---- record construction (mirrors KeyslotAdd's rng call order: salt, slot fill, stripes) ----
def add_labeled(rng, pw, flags, s):
    salt = rng.rand(32)
    rec = bytearray(rng.rand(STRIDE))
    payload = bytes([flags]) + VMK
    blob = af_split(payload, s, rng)
    ct_len = len(blob)
    rec[0:4] = b"VCKS"
    rec[4] = 2 if s >= 2 else 1
    rec[5] = 1
    rec[6:8] = int(s).to_bytes(2, "little") if s >= 2 else b"\x00\x00"
    rec[8:12] = COST.to_bytes(4, "little")
    rec[12:14] = PLEN.to_bytes(2, "little")
    rec[14:46] = salt
    aad = bytes(rec[0:L_CT])
    dk = kdf(pw, salt)
    ct = chacha20(dk[0:32], dk[32:40], blob)
    rec[L_CT:L_CT+ct_len] = ct
    rec[L_CT+ct_len:L_CT+ct_len+32] = hs256(dk[40:72], aad + ct)
    return bytes(rec)

def add_bare(rng, pw, flags, s):
    salt = rng.rand(32)
    rec = bytearray(rng.rand(STRIDE))
    payload = bytes([flags]) + VMK
    blob = af_split(payload, s, rng)
    ct_len = len(blob)
    rec[0:32] = salt
    aad = b"VCKSbare" + salt
    dk = kdf(pw, salt)
    ct = chacha20(dk[0:32], dk[32:40], blob)
    rec[B_CT:B_CT+ct_len] = ct
    rec[B_CT+ct_len:B_CT+ct_len+32] = hs256(dk[40:72], aad + ct)
    return bytes(rec)

def open_labeled(area, pw, s):
    """Constant-time-search equivalent: try every slot with the cfg-derived layout."""
    ct_len = PLEN * s
    for i in range(AREA_SLOTS):
        rec = area[i*STRIDE:(i+1)*STRIDE]
        aad = rec[0:L_CT]
        salt = rec[14:46]
        dk = kdf(pw, salt)
        ct = rec[L_CT:L_CT+ct_len]
        tag = rec[L_CT+ct_len:L_CT+ct_len+32]
        if hmac.compare_digest(hs256(dk[40:72], aad + ct), tag):
            payload = af_merge(chacha20(dk[0:32], dk[32:40], ct), PLEN, s)
            return payload[0], payload[1:]
    return None

def open_bare(area, pw, s):
    ct_len = PLEN * s
    idx = deniable_index(pw)
    rec = area[idx*STRIDE:(idx+1)*STRIDE]
    salt = rec[0:32]
    aad = b"VCKSbare" + salt
    dk = kdf(pw, salt)
    ct = rec[B_CT:B_CT+ct_len]
    tag = rec[B_CT+ct_len:B_CT+ct_len+32]
    if hmac.compare_digest(hs256(dk[40:72], aad + ct), tag):
        payload = af_merge(chacha20(dk[0:32], dk[32:40], ct), PLEN, s)
        return payload[0], payload[1:]
    return None

def deniable_index(pw):
    h = hashlib.sha256(b"VCKSloc" + pw).digest()
    return int.from_bytes(h[0:4], "little") % AREA_SLOTS

def yn(b):
    return "YES" if b else "NO"

def main():
    # ===== labeled AF record =====
    area = bytearray(AREA_SLOTS * STRIDE)
    rng = Lcg(0xC0FFEE)
    rec = add_labeled(rng, b"af-alice", 0, AF_S)
    area[0:STRIDE] = rec          # first free slot = 0
    print("REF af labeled slot = 0")
    print("REF af labeled record = " + rec.hex())
    r = open_labeled(area, b"af-alice", AF_S)
    print("REF af labeled roundtrip = " + yn(r is not None and r[0] == 0 and r[1] == VMK))
    print("REF af labeled wrong pass rejected = " + yn(open_labeled(area, b"af-alicf", AF_S) is None))

    # partial remnant: zero the first stripe inside ct
    saved = area[L_CT:L_CT+PLEN]
    area[L_CT:L_CT+PLEN] = bytes(PLEN)
    print("REF af partial remnant defeated = " + yn(open_labeled(area, b"af-alice", AF_S) is None))
    area[L_CT:L_CT+PLEN] = saved

    # cfg/record mismatch both ways + coexistence with a legacy record in slot 1
    no1 = open_labeled(area, b"af-alice", 1) is None
    rng = Lcg(0xBEEF)
    recL = add_labeled(rng, b"leg-bob", 0, 1)
    area[STRIDE:2*STRIDE] = recL   # first free slot = 1
    no2 = open_labeled(area, b"leg-bob", AF_S) is None
    print("REF af cfg mismatch rejected = " + yn(no1 and no2))
    ok1 = open_labeled(area, b"leg-bob", 1) is not None
    ok2 = open_labeled(area, b"af-alice", AF_S) is not None
    print("REF af legacy coexists = " + yn(ok1 and ok2))

    # ===== bare (deniable) AF record =====
    rng = Lcg(0xD0D0)
    area = bytearray(rng.rand(AREA_SLOTS * STRIDE))
    idx = deniable_index(b"af-denia")
    rec = add_bare(rng, b"af-denia", 1, AF_S)   # flags = KEYSLOT_FLAG_DURESS
    area[idx*STRIDE:(idx+1)*STRIDE] = rec
    print("REF af bare slot = %d" % idx)
    print("REF af bare record = " + rec.hex())
    r = open_bare(area, b"af-denia", AF_S)
    print("REF af bare roundtrip = " + yn(r is not None and r[0] == 1 and r[1] == VMK))

if __name__ == "__main__":
    main()
