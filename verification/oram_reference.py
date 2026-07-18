#!/usr/bin/env python3
"""
oram_reference.py — independent reference for the write-only ORAM PoC (docs/ORAM-SPEC.md).

Write-only ORAM (HIVE / DataLair family) is the real mitigation for the multi-snapshot deniability
attack (THREAT-MODEL.md): an adversary who images the disk twice compares the two snapshots and, in a
plain hidden-volume system, can spot hidden-volume writes from the block-change pattern. Write-only
ORAM makes EVERY logical write touch the SAME distribution of physical blocks — k uniformly-random
blocks re-encrypted with fresh IND-CPA ciphertext — independent of which logical block was written and
of whether it belongs to the public or the hidden volume. So two snapshots reveal only "k random
blocks changed per write", identical whether or not a hidden volume was used. (Reads do not modify the
disk, so a snapshot adversary never sees them — that is what makes write-only ORAM cheaper than full
ORAM and the right tool for THIS adversary.)

This file is the independent Layer-1 reference; oram_poc.c drives the REAL in-tree ChaCha20. Both use
the same deterministic PRNG so the whole run is reproducible and diffed byte-for-byte.

Parameters (PoC): B logical blocks, N=3*B physical blocks, block=32 bytes, k blocks touched per write.
"""

import hashlib

B = 8
N = 24
K = 10
BLK = 32
M32 = (1 << 32) - 1
M64 = (1 << 64) - 1

# ---- deterministic PRNG: xorshift64* (identical in oram_poc.c) ----
class Rng:
    def __init__(self, seed): self.s = seed & M64
    def u64(self):
        x = self.s
        x ^= (x >> 12); x &= M64
        x ^= (x << 25) & M64
        x ^= (x >> 27)
        self.s = x & M64
        return (self.s * 0x2545F4914F6CDD1D) & M64

# ---- ChaCha20 (20 rounds), matching Crypto/chacha256.c layout (as in keyslot_reference.py) ----
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

ORAM_KEY = bytes((0x30+i) & 0xff for i in range(32))

class WriteOnlyOram:
    def __init__(self, seed):
        self.rng = Rng(seed)
        self.nonce = [bytes(8) for _ in range(N)]
        self.ct = [bytes(BLK) for _ in range(N)]          # physical ciphertext blocks
        self.plain = [bytes(BLK) for _ in range(N)]        # shadow plaintext (trusted-side model)
        self.posmap = [-1]*B
        self.occ = [False]*N
        self.trace = []                                    # per-write: sorted list of touched positions

    def _enc(self, pos, pt):
        nz = self.rng.u64().to_bytes(8, "little")
        self.nonce[pos] = nz
        self.ct[pos] = chacha20(ORAM_KEY, nz, pt)
        self.plain[pos] = pt

    def _sample(self, L):
        # k distinct uniform positions; require a free one OR posmap[L] present (PoC params make this sure)
        S = []
        while len(S) < K:
            p = self.rng.u64() % N
            if p not in S: S.append(p)
        assert any(not self.occ[p] for p in S) or (self.posmap[L] in S), "resample needed; raise N/K"
        return S

    def write(self, L, pt):
        assert 0 <= L < B and len(pt) == BLK
        S = self._sample(L)
        old = self.posmap[L]
        if old != -1 and old in S:
            home = old
        else:
            home = next(p for p in S if not self.occ[p])
            if old != -1:
                self.occ[old] = False                      # free the stale home (re-randomised when next sampled)
        self.occ[home] = True
        self.posmap[L] = home
        for p in S:                                        # re-encrypt every touched block with fresh ciphertext
            self._enc(p, pt if p == home else (self.plain[p] if self.occ[p] else bytes(BLK)))
        self.trace.append(sorted(S))

    def read(self, L):
        p = self.posmap[L]
        return bytes(BLK) if p == -1 else self.plain[p]

    def digest(self):
        h = hashlib.sha256()
        for p in range(N): h.update(self.nonce[p]); h.update(self.ct[p])
        h.update(bytes((x + 128) & 0xff for x in self.posmap))
        return h.hexdigest()

def run_workload(hidden_active, seed=0x1234567890ABCDEF):
    """10 writes. Public addresses 0..3; 'hidden' addresses 4..7. When hidden_active is False the same
    number of writes all target public addresses, so the OBSERVABLE (per-write touched sets) has the
    same shape either way — that is the deniability property."""
    o = WriteOnlyOram(seed)
    pub = [0,1,2,3]; hid = [4,5,6,7]
    seq = ([0,4,1,5,2,6,3,7,0,1] if hidden_active else [0,1,2,3,0,1,2,3,0,1])
    for i, L in enumerate(seq):
        o.write(L, bytes(((L*7 + i*13 + j) & 0xff) for j in range(BLK)))
    return o

def main():
    # correctness: write then read back
    o = WriteOnlyOram(0xDEADBEEFCAFEF00D)
    vals = {}
    for i, L in enumerate([0,3,3,7,1,7,2,0,5,3]):
        v = bytes(((i*31 + L + j) & 0xff) for j in range(BLK)); o.write(L, v); vals[L] = v
    ok = all(o.read(L) == vals[L] for L in vals)
    print("REF correctness reads==writes = " + ("YES" if ok else "NO"))
    print("REF state digest = " + o.digest())

    # access-pattern indistinguishability. Each write draws its K touched positions from the PRNG
    # stream independent of the logical target, so the OBSERVABLE trace (which physical blocks change
    # per write) is IDENTICAL for a public-only workload and a public+hidden workload of the same
    # length — a snapshot adversary sees the same pattern either way and cannot detect hidden activity.
    a = run_workload(False); b = run_workload(True)
    same_trace = a.trace == b.trace
    all_k = all(len(t) == K for t in a.trace + b.trace)
    print("REF every write touches exactly K blocks = " + ("YES" if all_k else "NO"))
    print("REF access trace identical: public-only vs public+hidden = " + ("YES" if same_trace else "NO"))
    # ...while the encrypted contents of course differ (different data was written): confidentiality
    # is provided by the block cipher, deniability by the identical access pattern above.
    print("REF ciphertext differs though access pattern is identical = "
          + ("YES" if (same_trace and a.digest() != b.digest()) else "NO"))

if __name__ == "__main__":
    main()
