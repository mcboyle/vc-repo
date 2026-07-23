#!/usr/bin/env python3
# Independent reference for ML-KEM-768 (FIPS 203, final, Aug 2024) + the fork's
# PQ/classical hybrid combiner (docs/NETWORK-SHARE-SPEC.md direction). ML-KEM is
# NIST's standardized lattice KEM (Kyber): KeyGen -> (ek, dk); Encaps(ek) ->
# (K, c); Decaps(dk, c) -> K, with implicit rejection (a bad ciphertext yields
# a pseudorandom key derived from the secret z, never an error oracle).
#
# Why the fork wants a PQ HYBRID: the network-share / OPRF exchanges
# (McCallum-Relyea, docs/NETWORK-SHARE-SPEC.md) ride classical EC/DH. An
# adversary who records that traffic today can decrypt it later with a quantum
# computer ("harvest now, decrypt later") -- exactly the long-lived-secret
# threat a disk-encryption factor must survive. The combiner keys the derived
# tag on classical_ss || mlkem_ss, so a break of EITHER component alone
# (quantum breaks the EC exchange, or a lattice cryptanalysis breaks ML-KEM)
# still leaves the attacker without the key; both must fall. The tag also binds
# the ML-KEM transcript (H(ek), H(c)) so the hybrid secret is
# session-specific -- the usual IND-CCA hedge for hybrid KEMs.
#
# Vectors: official NIST ACVP FIPS-203 ML-KEM-768 vectors (usnistgov/ACVP-Server
# internalProjection.json, see mlkem_kats.py provenance note), including 5
# modified-ciphertext DECAPS cases that exercise implicit rejection. The C side
# prints the same REF lines; build_and_verify.sh diffs them byte-for-byte.
import hashlib
import hmac
import sys

import mlkem_kats

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4


def bitrev7(i):
    r = 0
    for b in range(7):
        r |= ((i >> b) & 1) << (6 - b)
    return r


ZETAS = [pow(17, bitrev7(i), Q) for i in range(128)]


# ---------------------------------------------------------------- NTT domain

def ntt(f):
    f = list(f)
    i = 1
    ln = 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = (z * f[j + ln]) % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def intt(f):
    f = list(f)
    i = 127
    ln = 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = (z * (f[j + ln] - t)) % Q
        ln *= 2
    return [(x * 3303) % Q for x in f]  # 3303 = 128^-1 mod q


def multiply_ntts(a, b):
    c = [0] * 256
    for i in range(128):
        gamma = pow(17, 2 * bitrev7(i) + 1, Q)
        c[2 * i] = (a[2 * i] * b[2 * i] + a[2 * i + 1] * b[2 * i + 1] * gamma) % Q
        c[2 * i + 1] = (a[2 * i] * b[2 * i + 1] + a[2 * i + 1] * b[2 * i]) % Q
    return c


def poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


# ---------------------------------------------------------------- sampling

def sample_ntt(seed34):
    xof = hashlib.shake_128(seed34)
    # squeeze a generous buffer; extend if the rejection rate is unlucky
    buf = xof.digest(3 * 1024)
    f = []
    pos = 0
    while len(f) < 256:
        if pos + 3 > len(buf):
            buf = xof.digest(len(buf) * 2)
        b0, b1, b2 = buf[pos], buf[pos + 1], buf[pos + 2]
        pos += 3
        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 // 16) + 16 * b2
        if d1 < Q:
            f.append(d1)
        if d2 < Q and len(f) < 256:
            f.append(d2)
    return f


def sample_cbd(data, eta):
    # 64*eta bytes as a little-endian bitstream
    bits = []
    for byte in data:
        for b in range(8):
            bits.append((byte >> b) & 1)
    f = []
    for i in range(256):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[(2 * i + 1) * eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


def prf(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def G(data):
    d = hashlib.sha3_512(data).digest()
    return d[:32], d[32:]


def H(data):
    return hashlib.sha3_256(data).digest()


def J(data):
    return hashlib.shake_256(data).digest(32)


# ---------------------------------------------------------------- coding

def compress(x, d):
    return (((x << d) + 1664) // Q) % (1 << d)


def decompress(y, d):
    return (y * Q + (1 << (d - 1))) >> d


def byte_encode(f, d):
    bits = []
    for c in f:
        for b in range(d):
            bits.append((c >> b) & 1)
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i // 8] |= bit << (i % 8)
    return bytes(out)


def byte_decode(data, d):
    bits = []
    for byte in data:
        for b in range(8):
            bits.append((byte >> b) & 1)
    f = []
    for i in range(256):
        c = 0
        for b in range(d):
            c |= bits[i * d + b] << b
        f.append(c)
    return f


# ---------------------------------------------------------------- K-PKE

def gen_matrix(rho):
    # A_hat[i][j] = SampleNTT(rho || byte(j) || byte(i))  -- j BEFORE i
    return [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def kpke_keygen(d32):
    rho, sigma = G(d32 + bytes([K]))  # the appended 0x03 is REQUIRED (FIPS 203 final)
    a_hat = gen_matrix(rho)
    n = 0
    s = []
    for i in range(K):
        s.append(sample_cbd(prf(ETA1, sigma, n), ETA1))
        n += 1
    e = []
    for i in range(K):
        e.append(sample_cbd(prf(ETA1, sigma, n), ETA1))
        n += 1
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = poly_add(acc, multiply_ntts(a_hat[i][j], s_hat[j]))
        t_hat.append(poly_add(acc, e_hat[i]))
    ek = b"".join(byte_encode(t_hat[i], 12) for i in range(K)) + rho
    dk = b"".join(byte_encode(s_hat[i], 12) for i in range(K))
    return ek, dk


def kpke_encrypt(ek, m32, r32):
    t_hat = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(K)]
    rho = ek[1152:1184]
    a_hat = gen_matrix(rho)
    n = 0
    y = []
    for i in range(K):
        y.append(sample_cbd(prf(ETA1, r32, n), ETA1))
        n += 1
    e1 = []
    for i in range(K):
        e1.append(sample_cbd(prf(ETA2, r32, n), ETA2))
        n += 1
    e2 = sample_cbd(prf(ETA2, r32, n), ETA2)
    y_hat = [ntt(p) for p in y]
    u = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = poly_add(acc, multiply_ntts(a_hat[j][i], y_hat[j]))  # transposed
        u.append(poly_add(intt(acc), e1[i]))
    mu = [decompress(c, 1) for c in byte_decode(m32, 1)]
    acc = [0] * 256
    for j in range(K):
        acc = poly_add(acc, multiply_ntts(t_hat[j], y_hat[j]))
    v = poly_add(poly_add(intt(acc), e2), mu)
    c1 = b"".join(byte_encode([compress(x, DU) for x in u[i]], DU) for i in range(K))
    c2 = byte_encode([compress(x, DV) for x in v], DV)
    return c1 + c2


def kpke_decrypt(dk, c):
    u = [[decompress(x, DU) for x in byte_decode(c[320 * i:320 * (i + 1)], DU)]
         for i in range(K)]
    v = [decompress(x, DV) for x in byte_decode(c[960:1088], DV)]
    s_hat = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(K)]
    acc = [0] * 256
    for j in range(K):
        acc = poly_add(acc, multiply_ntts(s_hat[j], ntt(u[j])))
    w = poly_sub(v, intt(acc))
    return byte_encode([compress(x, 1) for x in w], 1)


# ---------------------------------------------------------------- ML-KEM

def mlkem_keygen(d32, z32):
    ek_pke, dk_pke = kpke_keygen(d32)
    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z32
    return ek, dk


def mlkem_encaps(ek, m32):
    k, r = G(m32 + H(ek))
    c = kpke_encrypt(ek, m32, r)
    return k, c


def mlkem_decaps(dk, c):
    dk_pke = dk[0:1152]
    ek = dk[1152:2336]
    h = dk[2336:2368]
    z = dk[2368:2400]
    m = kpke_decrypt(dk_pke, c)
    kp, rp = G(m + h)
    kbar = J(z + c)
    cp = kpke_encrypt(ek, m, rp)
    if c != cp:
        kp = kbar  # implicit rejection
    return kp


# ---------------------------------------------------------------- hybrid

def hybrid_tag(classical_ss, mlkem_ss, ek, c):
    msg = (b"VC-HYBRID-v1" + hashlib.sha256(ek).digest()
           + hashlib.sha256(c).digest())
    return hmac.new(classical_ss + mlkem_ss, msg, hashlib.sha256).digest()


if __name__ == "__main__":
    ok = True

    # --- keygen ---
    kg_match = True
    for i, (d, z, ek_ref, dk_ref) in enumerate(mlkem_kats.KEYGEN):
        ek, dk = mlkem_keygen(bytes.fromhex(d), bytes.fromhex(z))
        print("REF keygen_%d_ek_sha256 %s" % (i, hashlib.sha256(ek).hexdigest()))
        print("REF keygen_%d_dk_sha256 %s" % (i, hashlib.sha256(dk).hexdigest()))
        if ek != bytes.fromhex(ek_ref) or dk != bytes.fromhex(dk_ref):
            kg_match = False
    print("REF keygen_all_match " + ("YES" if kg_match else "NO"))
    ok &= kg_match

    # --- encaps ---
    en_match = True
    for i, (ek_hex, m, c_ref, k_ref) in enumerate(mlkem_kats.ENCAPS):
        k, c = mlkem_encaps(bytes.fromhex(ek_hex), bytes.fromhex(m))
        print("REF encaps_%d_c_sha256 %s" % (i, hashlib.sha256(c).hexdigest()))
        print("REF encaps_%d_k %s" % (i, k.hex()))
        if c != bytes.fromhex(c_ref) or k != bytes.fromhex(k_ref):
            en_match = False
    print("REF encaps_all_match " + ("YES" if en_match else "NO"))
    ok &= en_match

    # --- decaps (incl. implicit-rejection cases) ---
    de_match = True
    rejects = 0
    for i, (dk_hex, c_hex, k_ref, reason) in enumerate(mlkem_kats.DECAPS):
        k = mlkem_decaps(bytes.fromhex(dk_hex), bytes.fromhex(c_hex))
        print("REF decaps_%d_k %s" % (i, k.hex()))
        if k != bytes.fromhex(k_ref):
            de_match = False
        if "modified ciphertext" in reason:
            rejects += 1
    print("REF decaps_all_match " + ("YES" if de_match else "NO"))
    print("REF implicit_rejection_cases %d" % rejects)
    ok &= de_match and rejects == 5

    # --- hybrid combiner (ENCAPS vector 0) ---
    ek0, _, c0, k0 = mlkem_kats.ENCAPS[0]
    ek_b = bytes.fromhex(ek0)
    c_b = bytes.fromhex(c0)
    k_b = bytes.fromhex(k0)
    classical = bytes((i * 7 + 1) % 256 for i in range(32))
    tag = hybrid_tag(classical, k_b, ek_b, c_b)
    print("REF hybrid_tag %s" % tag.hex())
    cl2 = bytes([classical[0] ^ 0x01]) + classical[1:]
    k2 = bytes([k_b[0] ^ 0x01]) + k_b[1:]
    needs_both = (hybrid_tag(cl2, k_b, ek_b, c_b) != tag
                  and hybrid_tag(classical, k2, ek_b, c_b) != tag)
    print("REF hybrid_needs_both " + ("YES" if needs_both else "NO"))
    ok &= needs_both

    sys.exit(0 if ok else 1)
