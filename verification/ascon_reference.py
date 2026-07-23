#!/usr/bin/env python3
# Independent Ascon-Hash256 reference (docs/HASHES-SPEC.md, IDEAS-BACKLOG.md
# "Hashes" row). Ascon (Dobraunig, Eichlseder, Mendel, Schläffer) is the NIST
# Lightweight Cryptography winner, standardized in SP 800-232 (2025).
# Ascon-Hash256: 320-bit state (5 x 64-bit words), 12-round permutation, rate 8.
# Candidate as a compact hash for constrained/embedded targets in scope.
# NOT in the VeraCrypt tree: proof = official NIST ACVP vectors (ascon_kats.py)
# + byte-identical agreement with ascon_poc.c. Stdlib only.
import sys
import ascon_kats

M64 = (1 << 64) - 1

def _ror(x, n):
    return ((x >> n) | (x << (64 - n))) & M64

def _perm(S, rounds):
    for r in range(12 - rounds, 12):
        S[2] ^= (0xf0 - r * 0x10 + r)          # round constant
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]   # substitution layer (chi)
        T = [((S[i] ^ M64) & S[(i + 1) % 5]) for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= M64
        S[0] ^= _ror(S[0], 19) ^ _ror(S[0], 28)
        S[1] ^= _ror(S[1], 61) ^ _ror(S[1], 39)
        S[2] ^= _ror(S[2], 1) ^ _ror(S[2], 6)
        S[3] ^= _ror(S[3], 10) ^ _ror(S[3], 17)
        S[4] ^= _ror(S[4], 7) ^ _ror(S[4], 41)
    return S

def ascon_hash256(msg):
    # IV per SP 800-232: [version=2,0,(12<<4)|12] || taglen(256, 2 bytes BE) || [rate=8,0,0]
    # IV per SP 800-232 (little-endian state words, as in the reference):
    # [version=2, 0, (12<<4)|12] || taglen(256, 2 bytes LE) || [rate=8, 0, 0]
    iv = bytes([2, 0, 0xCC]) + (256).to_bytes(2, 'little') + bytes([8, 0, 0])
    S = [int.from_bytes(iv, 'little'), 0, 0, 0, 0]
    _perm(S, 12)
    # absorb, rate = 8 bytes; pad with a single 0x01 byte then zeros
    m = msg + b'\x01' + b'\x00' * ((-(len(msg) + 1)) % 8)
    for i in range(0, len(m), 8):
        S[0] ^= int.from_bytes(m[i:i+8], 'little')
        _perm(S, 12)
    # squeeze 32 bytes
    out = b''
    for _ in range(4):
        out += (S[0]).to_bytes(8, 'little')
        _perm(S, 12)
    return out[:32]

if __name__ == "__main__":
    all_ok = True
    for i, (msg_hex, md_hex) in enumerate(ascon_kats.KATS):
        got = ascon_hash256(bytes.fromhex(msg_hex)).hex()
        print("REF md_%d %s" % (i, got))
        all_ok = all_ok and got == md_hex.lower()
    print("REF all_match " + ("YES" if all_ok else "NO"))
    sys.exit(0 if all_ok else 1)
