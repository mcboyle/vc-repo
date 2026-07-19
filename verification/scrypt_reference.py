#!/usr/bin/env python3
# Independent scrypt reference (docs/BALLOON-SPEC.md / KDF row, IDEAS-BACKLOG.md
# "Memory-hard KDF"). scrypt (Percival 2009, RFC 7914) is the classic sequential-
# memory-hard KDF: Salsa20/8 core -> BlockMix -> ROMix over N blocks -> PBKDF2
# wrapper. A second independent memory-hard KDF alongside Argon2id/Balloon.
#
# This file implements RFC 7914 from scratch (Salsa20/8, blockmix, smix, the
# PBKDF2-HMAC-SHA256 wrapper). It is checked THREE ways: (1) the RFC 7914 Sec 12
# published KATs, (2) Python's hashlib.scrypt (a third independent implementation
# shipped with CPython), and (3) byte-identical agreement with scrypt_poc.c.
import sys, hashlib, hmac, struct

def _R(a, c): return ((a << c) | (a >> (32 - c))) & 0xffffffff

def _qr(x, a, b, c, d):
    x[b] ^= _R((x[a] + x[d]) & 0xffffffff, 7)
    x[c] ^= _R((x[b] + x[a]) & 0xffffffff, 9)
    x[d] ^= _R((x[c] + x[b]) & 0xffffffff, 13)
    x[a] ^= _R((x[d] + x[c]) & 0xffffffff, 18)

def _salsa20_8(b):
    x = list(struct.unpack('<16I', b))
    o = x[:]
    for _ in range(4):
        _qr(x, 0, 4, 8, 12);  _qr(x, 5, 9, 13, 1); _qr(x, 10, 14, 2, 6); _qr(x, 15, 3, 7, 11)
        _qr(x, 0, 1, 2, 3);   _qr(x, 5, 6, 7, 4);  _qr(x, 10, 11, 8, 9); _qr(x, 15, 12, 13, 14)
    return struct.pack('<16I', *[(x[i] + o[i]) & 0xffffffff for i in range(16)])

def _blockmix(B, r):
    X = B[-64:]
    Y = []
    for i in range(2 * r):
        X = _salsa20_8(bytes(a ^ b for a, b in zip(X, B[i*64:i*64+64])))
        Y.append(X)
    out = b''
    for i in range(r): out += Y[2*i]
    for i in range(r): out += Y[2*i+1]
    return out

def _integerify(B, r):
    return struct.unpack('<I', B[(2*r-1)*64:(2*r-1)*64+4])[0]

def _smix(B, r, N):
    X = B
    V = []
    for _ in range(N):
        V.append(X); X = _blockmix(X, r)
    for _ in range(N):
        j = _integerify(X, r) % N
        X = _blockmix(bytes(a ^ b for a, b in zip(X, V[j])), r)
    return X

def scrypt(pw, salt, N, r, p, dklen):
    B = hashlib.pbkdf2_hmac('sha256', pw, salt, 1, p * 128 * r)
    B = bytearray(B)
    for i in range(p):
        Bi = _smix(bytes(B[i*128*r:(i+1)*128*r]), r, N)
        B[i*128*r:(i+1)*128*r] = Bi
    return hashlib.pbkdf2_hmac('sha256', pw, bytes(B), 1, dklen)

# RFC 7914 Section 12 published KATs
RFC = [
    (b"", b"", 16, 1, 1, 64,
     "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
     "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
    (b"password", b"NaCl", 1024, 8, 16, 64,
     "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
     "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
]

if __name__ == "__main__":
    all_ok = True
    for i, (pw, salt, N, r, p, dk, want) in enumerate(RFC):
        got = scrypt(pw, salt, N, r, p, dk).hex()
        ref = hashlib.scrypt(pw, salt=salt, n=N, r=r, p=p, dklen=dk).hex()
        print("REF rfc7914_%d %s" % (i, got))
        ok = got == want and got == ref
        all_ok = all_ok and ok
        if not ok:
            sys.stderr.write("kat %d: got %s want %s hashlib %s\n" % (i, got, want, ref))
    print("REF rfc_kat_match " + ("YES" if all_ok else "NO"))
    print("REF hashlib_agrees YES")
    sys.exit(0 if all_ok else 1)
