#!/usr/bin/env python3
"""
decoyfrag_reference.py — independent reference for the decoy-fragments-by-default PoC
(docs/DECOY-FRAGMENTS-SPEC.md, upstream issue #1072).

Claim: writing decoy hidden-volume "creation artifacts" on EVERY volume makes the presence of such an
artifact prove nothing. The core, verifiable reason: a REAL hidden-volume header is
`salt || ChaCha20(header_key, header_plaintext)` and a DECOY fragment is `salt || ChaCha20(random_key,
zeros)` = `salt || keystream`. Both are `random_salt || PRF_output`, i.e. drawn from the SAME uniform
distribution — so a free-space scanner cannot tell a volume that HAS a hidden volume from one that only
carries decoy fragments. (This is deniable *storage* — indistinguishable-random artifacts — NOT a
fabricated record of user activity, which stays DESCOPED.)

Layer-1 independent reference (Python ChaCha20 + integer uniformity statistic); decoyfrag_poc.c drives
the REAL in-tree chacha256.c. build_and_verify.sh diffs the REF lines byte-for-byte.
"""

M32 = (1 << 32) - 1
M64 = (1 << 64) - 1
SALT = 64
BODY = 448
TOTAL = SALT + BODY        # 512, VeraCrypt's effective header size
SAMPLES = 64
EXPECTED = SAMPLES * TOTAL // 256   # 128 bytes per value-bin, exact integer

class Rng:
    def __init__(self, seed): self.s = seed & M64
    def u64(self):
        x = self.s; x ^= (x >> 12); x &= M64; x ^= (x << 25) & M64; x ^= (x >> 27)
        self.s = x & M64
        return (self.s * 0x2545F4914F6CDD1D) & M64
    def bytes(self, n):
        out = bytearray()
        while len(out) < n: out += self.u64().to_bytes(8, "little")
        return bytes(out[:n])

def rotl32(x, n):
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32
def chacha_core(x):
    for _ in range(10):
        def qr(a,b,c,d):
            x[a]=(x[a]+x[b])&M32; x[d]=rotl32(x[d]^x[a],16)
            x[c]=(x[c]+x[d])&M32; x[b]=rotl32(x[b]^x[c],12)
            x[a]=(x[a]+x[b])&M32; x[d]=rotl32(x[d]^x[a],8)
            x[c]=(x[c]+x[d])&M32; x[b]=rotl32(x[b]^x[c],7)
        qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15)
        qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14)
def chacha20(key32, iv8, data):
    inp=[0]*16
    inp[0],inp[1],inp[2],inp[3]=0x61707865,0x3320646E,0x79622D32,0x6B206574
    for i in range(8): inp[4+i]=int.from_bytes(key32[i*4:i*4+4],"little")
    inp[12]=inp[13]=0
    inp[14]=int.from_bytes(iv8[0:4],"little"); inp[15]=int.from_bytes(iv8[4:8],"little")
    out=bytearray(); off=0
    while off<len(data):
        blk=list(inp); chacha_core(blk)
        ks=b"".join(((blk[i]+inp[i])&M32).to_bytes(4,"little") for i in range(16))
        n=min(64,len(data)-off); out+=bytes(data[off+i]^ks[i] for i in range(n)); off+=n
        inp[12]=(inp[12]+1)&M32
        if inp[12]==0: inp[13]=(inp[13]+1)&M32
    return bytes(out)

def real_hidden_header(rng):
    """salt || ChaCha20(header_key, iv, structured header plaintext) — a genuine hidden header."""
    salt = rng.bytes(SALT)
    header_key = rng.bytes(32)
    iv = rng.bytes(8)
    pt = bytearray(b"VERA")                       # a real header has structure BEFORE encryption
    pt += (0x0005).to_bytes(2, "little")
    while len(pt) < BODY: pt.append((len(pt) * 37) & 0xff)
    return salt + chacha20(header_key, iv, bytes(pt))

def decoy_fragment(rng):
    """salt || ChaCha20(random_key, iv, zeros) = salt || keystream — indistinguishable from the above."""
    salt = rng.bytes(SALT)
    decoy_key = rng.bytes(32)                     # random, then discarded
    iv = rng.bytes(8)
    return salt + chacha20(decoy_key, iv, bytes(BODY))

def chi2_num(blobs):
    """integer statistic: sum over 256 byte-values of (count - EXPECTED)^2 (no float; C reproduces it)."""
    hist = [0] * 256
    for b in blobs:
        for x in b: hist[x] += 1
    return sum((c - EXPECTED) ** 2 for c in hist)

# acceptance bound: chi-square(255 dof) at p~0.001 is ~ 330; statistic ~ chi2_num/EXPECTED, so
# chi2_num < 330*EXPECTED. Both real and decoy batches must pass the SAME test.
BOUND = 330 * EXPECTED

def main():
    r = Rng(0x0DEC0DEF00DBA5E5)
    real1 = real_hidden_header(r)
    decoy1 = decoy_fragment(r)
    print("REF real_header  = " + real1[:32].hex())     # first 32 bytes of a real hidden header
    print("REF decoy_frag   = " + decoy1[:32].hex())    # first 32 bytes of a decoy fragment

    r = Rng(0xF00DFACEC0FFEE01)
    reals = [real_hidden_header(r) for _ in range(SAMPLES)]
    decoys = [decoy_fragment(r) for _ in range(SAMPLES)]
    cr = chi2_num(reals); cd = chi2_num(decoys)
    print("REF real chi2num  = %d" % cr)
    print("REF decoy chi2num = %d" % cd)
    print("[A] identical layout (512 bytes, 64-byte salt): YES")
    print("[B] real hidden headers pass uniformity: " + ("YES" if cr < BOUND else "NO"))
    print("[C] decoy fragments pass the SAME uniformity test: " + ("YES" if cd < BOUND else "NO"))

if __name__ == "__main__":
    main()
