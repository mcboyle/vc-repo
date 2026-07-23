#!/usr/bin/env python3
# Independent Poly1305 reference (RFC 8439). Big-integer arithmetic, deliberately
# the most transparent possible implementation: no radix tricks, no carries by hand.
# Used to cross-check verification/poly1305_poc.c (radix-2^26 "donna" one-shot)
# byte-for-byte. Poly1305 is NOT in the VeraCrypt tree, so the two independent
# references here are (a) this bigint code and (b) the RFC 8439 published KATs.
import sys

P = (1 << 130) - 5

def clamp(r):
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def poly1305_mac(msg, key):
    assert len(key) == 32
    r = clamp(int.from_bytes(key[0:16], 'little'))
    s = int.from_bytes(key[16:32], 'little')
    acc = 0
    i = 0
    n = len(msg)
    while i < n:
        block = msg[i:i+16]
        # append the 1 bit beyond the block bytes (2^(8*len))
        m = int.from_bytes(block, 'little') | (1 << (8 * len(block)))
        acc = (acc + m) % P
        acc = (acc * r) % P
        i += 16
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, 'little')

# RFC 8439 §2.5.2 worked example
def rfc_vector():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b")
    msg = b"Cryptographic Forum Research Group"
    tag = poly1305_mac(msg, key)
    return tag.hex()

# RFC 8439 A.3 test vectors (a subset with distinct shapes)
# RFC 8439 A.3 test vectors (a subset with distinct shapes).
# #1: 32-byte all-zero key over a 64-byte all-zero message -> zero tag (r=0, s=0).
# #2: r = 0, s = 36e5..863e over the "IETF submission" note, so tag == s.
_A3_2_MSG = (
    b"Any submission to the IETF intended by the Contributor for publication "
    b"as all or part of an IETF Internet-Draft or RFC and any statement made "
    b"within the context of an IETF activity is considered an \"IETF "
    b"Contribution\". Such statements include oral statements in IETF "
    b"sessions, as well as written and electronic communications made at any "
    b"time or place, which are addressed to")
A3 = [
    # (key bytes, msg bytes, expected tag hex)
    (bytes(32), bytes(64), "00000000000000000000000000000000"),
    (bytes(16) + bytes.fromhex("36e5f6b5c5e06070f0efca96227a863e"),
     _A3_2_MSG, "36e5f6b5c5e06070f0efca96227a863e"),
]

def a3():
    out = []
    for k, m, th in A3:
        tag = poly1305_mac(m, k).hex()
        out.append((tag, th, tag == th))
    return out

def _fuzz():
    # Reproduce poly1305_poc.c's xorshift64* stream byte-for-byte.
    MASK = (1 << 64) - 1
    st = 0x243f6a8885a308d3
    def nextbyte():
        nonlocal st
        st ^= (st >> 12); st &= MASK
        st ^= (st << 25) & MASK
        st ^= (st >> 27)
        return ((st * 0x2545F4914F6CDD1D) & MASK) >> 40 & 0xff
    lengths = [0,1,2,15,16,17,31,32,33,47,48,49,63,64,65,100,127,128,129,255,256,300]
    out = []
    for L in lengths:
        key = bytes(nextbyte() for _ in range(32))
        msg = bytes(nextbyte() for _ in range(L))
        out.append((L, poly1305_mac(msg, key).hex()))
    return out

if __name__ == "__main__":
    print("REF rfc_2.5.2 " + rfc_vector())
    for idx, (got, want, ok) in enumerate(a3()):
        print("REF a3_%d %s" % (idx, got))
        if not ok:
            sys.stderr.write("A.3 #%d mismatch: got %s want %s\n" % (idx, got, want))
    for L, tag in _fuzz():
        print("REF fuzz_%d %s" % (L, tag))
