#!/usr/bin/env python3
"""
afsplit_reference.py — independent reference for anti-forensic (AF) splitting (docs/AF-SPLIT-SPEC.md,
IDEAS-BACKLOG.md P0.3).

The concrete answer to the SSD-remnant caveat (THREAT-MODEL.md): before a keyslot's wrapped key is
written, diffuse it across s "stripes" (LUKS/TKS1 AFsplit) so that recovering the key requires ALL s
stripes. A partial recovery — the wear-leveling remnant an SSD may leave behind — yields nothing,
because every stripe is needed and any missing stripe leaves the result uniformly random.

split:  buf = 0
        for i in 0..s-2:  stripe[i] = random;  buf = diffuse(buf XOR stripe[i])
        stripe[s-1] = key XOR buf
merge:  buf = 0
        for i in 0..s-2:  buf = diffuse(buf XOR stripe[i])
        key = stripe[s-1] XOR buf
diffuse(x): SHA-256 each 32-byte section of x with its big-endian section index prepended (LUKS).

Layer-1 independent reference (Python hashlib); afsplit_poc.c drives the REAL in-tree Sha2.c.
build_and_verify.sh diffs the REF lines byte-for-byte.
"""

import hashlib

M64 = (1 << 64) - 1
N = 128        # material length (multiple of 32)
S = 4          # stripes
DS = 32        # SHA-256 digest size

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

def xorb(a, b): return bytes(x ^ y for x, y in zip(a, b))

def diffuse(src):
    out = bytearray(len(src))
    for i in range(len(src) // DS):
        out[i*DS:(i+1)*DS] = hashlib.sha256(i.to_bytes(4, "big") + src[i*DS:(i+1)*DS]).digest()
    return bytes(out)

def af_split(key, s, rng):
    n = len(key); stripes = []; buf = bytes(n)
    for _ in range(s - 1):
        st = rng.bytes(n); stripes.append(st); buf = diffuse(xorb(buf, st))
    stripes.append(xorb(key, buf))
    return stripes

def af_merge(stripes):
    n = len(stripes[0]); buf = bytes(n)
    for i in range(len(stripes) - 1):
        buf = diffuse(xorb(buf, stripes[i]))
    return xorb(stripes[-1], buf)

def main():
    key = bytes((0x60 + i) & 0xff for i in range(N))
    rng = Rng(0xA5F00DCAFEBABE01)
    stripes = af_split(key, S, rng)
    split_hash = hashlib.sha256(b"".join(stripes)).hexdigest()
    print("REF split total len = %d" % (len(stripes) * N))
    print("REF split hash = " + split_hash)

    merged = af_merge(stripes)
    print("REF merge recovers key = " + ("YES" if merged == key else "NO"))

    # any missing/corrupt stripe -> recovery reveals nothing (result != key)
    ok = True
    for drop in range(S):
        damaged = [bytes(N) if i == drop else stripes[i] for i in range(S)]
        if af_merge(damaged) == key: ok = False
    print("REF any missing stripe defeats recovery = " + ("YES" if ok else "NO"))
    # the last-stripe (key XOR buf) alone must not equal the key either
    print("REF final stripe alone != key = " + ("YES" if stripes[-1] != key else "NO"))

if __name__ == "__main__":
    main()
