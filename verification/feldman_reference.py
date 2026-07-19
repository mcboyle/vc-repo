#!/usr/bin/env python3
# Independent Feldman VSS reference (docs/VSS-SPEC.md, IDEAS-BACKLOG.md "Sharing"
# row). Plain Shamir (step [5]) splits a secret t-of-n but a MALICIOUS or buggy
# dealer can hand out inconsistent shares that reconstruct to different secrets
# depending on which subset combines -- undetectably. Feldman Verifiable Secret
# Sharing (1987) fixes that: the dealer publishes commitments C_j = g^{a_j} to
# the polynomial coefficients, and every shareholder checks its own share
# against them WITHOUT learning the secret. A cheated share is caught at
# distribution time, not at some future reconstruction.
#
#   f(x) = s + a_1 x + ... + a_{t-1} x^{t-1}  (mod q)   share_i = (i, f(i))
#   C_j  = g^{a_j} mod p        (a_0 = s)
#   verify i:  g^{share_i} == prod_j C_j^{(i^j)}   (mod p)
#
# Over the order-q subgroup of Z_p* (p a safe prime, g of order q). No standard
# KAT; proof = byte-identical agreement with feldman_poc.c + the verifiability
# properties (honest shares pass, tampered shares fail, t reconstruct). Stdlib.
import sys

P = 0x800000000000000000000000000000000000000000000000000000000002ff7f
Q = (P - 1) // 2
G = pow(2, 2, P)          # 2^2 has order q in Z_p* (safe prime => subgroup order q)

def _poly(coeffs, x):
    r = 0
    for c in reversed(coeffs):
        r = (r * x + c) % Q
    return r

def deal(secret, t, n, rand_coeffs):
    coeffs = [secret % Q] + [c % Q for c in rand_coeffs[:t - 1]]
    shares = [(i, _poly(coeffs, i)) for i in range(1, n + 1)]
    commits = [pow(G, c, P) for c in coeffs]
    return shares, commits

def verify_share(share, commits):
    i, y = share
    lhs = pow(G, y, P)
    rhs = 1
    for j, c in enumerate(commits):
        rhs = (rhs * pow(c, pow(i, j, Q), P)) % P
    return lhs == rhs

def reconstruct(shares):
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % Q
            den = (den * (xi - xj)) % Q
        s = (s + yi * num * pow(den, -1, Q)) % Q
    return s % Q

if __name__ == "__main__":
    secret = 0xC0FFEE1234567890FEDCBA9876543210DEADBEEFCAFEBABE1029384756AB
    T, N = 3, 5
    rc = [0x1111111111111111111111111111111111111111111111111111111111,
          0x2222222222222222222222222222222222222222222222222222222222]
    shares, commits = deal(secret, T, N, rc)
    for j, c in enumerate(commits):
        print("REF commit_%d %064x" % (j, c))
    for (i, y) in shares:
        print("REF share_%d %064x" % (i, y))
    all_ok = all(verify_share(s, commits) for s in shares)
    print("REF all_shares_verify " + ("YES" if all_ok else "NO"))
    bad = (shares[2][0], (shares[2][1] ^ 1))
    print("REF tampered_share_rejected " + ("YES" if not verify_share(bad, commits) else "NO"))
    rec = reconstruct([shares[0], shares[2], shares[4]])
    print("REF reconstruct_t %s" % ("YES" if rec == secret % Q else "NO"))
    bad_rec = reconstruct([shares[0], shares[1]])
    print("REF below_threshold_wrong %s" % ("YES" if bad_rec != secret % Q else "NO"))
    sys.exit(0 if all_ok and rec == secret % Q else 1)
