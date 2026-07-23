#!/usr/bin/env python3
# Independent threshold-OPRF reference (docs/OPRF-SPEC.md, IDEAS-BACKLOG.md §C /
# "Password protocols" row). The single-server OPRF (step [17]) has one point of
# failure/compromise. A THRESHOLD OPRF Shamir-splits the server key K across n
# servers; the client blinds once, sends the blinded element to t servers, and
# combines their partial evaluations via Lagrange-in-the-exponent to the SAME
# output as the single-key OPRF -- any t cooperate, t-1 learn nothing, and no
# server ever sees the password. (Baldimtsi et al.; the PPSS/TOPPSS line.)
#
# Reuses the exact group of oprf_reference.py (small primes for a fast KAT).
# Proven byte-identical to toprf_poc.c (real in-tree Sha2.c) + the threshold
# properties. Stdlib only.
import sys, hashlib

P = 17592186046427
Q = 8796093023213
G = 4

def _mul(a, b, m): return (a * b) % m
def _pow(b, e, m): return pow(b, e, m)

def Hq(pw):
    return int.from_bytes(hashlib.sha256(b"h2" + pw).digest()[:8], "big") % Q
def H2(pw):
    return _pow(G, Hq(pw), P)
def oprf_out(pw, U):
    return hashlib.sha256(b"oprf" + pw + U.to_bytes(8, "little")).digest()

def single(pw, K, r):
    A = _pow(H2(pw), r, P)
    B = _pow(A, K, P)
    U = _pow(B, _pow(r, Q - 2, Q), P)
    return oprf_out(pw, U)

# Shamir over Z_Q: f(0)=K
def split(K, t, n, coeffs):
    c = [K % Q] + [x % Q for x in coeffs[:t - 1]]
    def f(x):
        r = 0
        for a in reversed(c): r = (r * x + a) % Q
        return r
    return [(i, f(i)) for i in range(1, n + 1)]

def lagrange0(idxs):
    lam = {}
    for i in idxs:
        num, den = 1, 1
        for j in idxs:
            if i == j: continue
            num = (num * (-j)) % Q
            den = (den * (i - j)) % Q
        lam[i] = (num * pow(den, -1, Q)) % Q
    return lam

def threshold(pw, shares_subset, r):
    A = _pow(H2(pw), r, P)                       # client blinds once
    idxs = [i for (i, _) in shares_subset]
    lam = lagrange0(idxs)
    B = 1
    for (i, ki) in shares_subset:                # each server returns A^{k_i}, sees only A
        Bi = _pow(A, ki, P)
        B = _mul(B, _pow(Bi, lam[i], P), P)      # combine in the exponent
    U = _pow(B, _pow(r, Q - 2, Q), P)
    return oprf_out(pw, U), A

if __name__ == "__main__":
    pw = b"correct horse battery staple"
    K = 0x0123456789ABC % Q
    T, N = 3, 5
    shares = split(K, T, N, [0x1111111111, 0x2222222222])
    r = 0xABCDEF123456 % Q

    base = single(pw, K, r)
    print("REF single_output " + base.hex())
    out135, A = threshold(pw, [shares[0], shares[2], shares[4]], r)
    print("REF threshold_A %016x" % A)
    print("REF threshold_output " + out135.hex())
    print("REF threshold_matches_single " + ("YES" if out135 == base else "NO"))
    out245, _ = threshold(pw, [shares[1], shares[3], shares[4]], r)
    print("REF any_t_subset_agrees " + ("YES" if out245 == base else "NO"))
    # below threshold: 2 servers -> wrong key -> different output
    bad, _ = threshold(pw, shares[:2], r)
    print("REF below_threshold_differs " + ("YES" if bad != base else "NO"))
    # a server sees only the blinded A, never H2(pw)
    print("REF server_sees_only_blinded " + ("YES" if A != H2(pw) else "NO"))
    sys.exit(0 if out135 == base else 1)
