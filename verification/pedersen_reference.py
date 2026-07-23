#!/usr/bin/env python3
# Independent Pedersen VSS reference (docs/VSS-SPEC.md, IDEAS-BACKLOG.md
# "Sharing" row). Feldman VSS (step [31]) publishes C_j = g^{a_j}: binding, but
# only computationally hiding (a dlog break reveals the coefficients — including
# the secret). Pedersen VSS (1991) blinds every coefficient with a second
# polynomial under an independent generator h:
#
#   f(x) = s + a_1 x + ...,   b(x) = r + b_1 x + ...   (both mod q)
#   C_j  = g^{a_j} h^{b_j} mod p          share_i = (i, f(i), b(i))
#   verify i:  g^{f(i)} h^{b(i)} == prod_j C_j^{(i^j mod q)}   (mod p)
#
# The commitments are perfectly hiding (any secret is consistent with them for
# SOME blinding), and binding as long as nobody knows log_g(h). Same group as
# Feldman: order-q subgroup of Z_p*, p a safe prime; g = 2^2, h = 3^2 (both
# QRs, mutual dlog unknown — a production deployment derives h verifiably,
# e.g. hash-to-group). No standard KAT; proof = byte-identical agreement with
# pedersen_poc.c + the verifiability properties. Stdlib only.
import sys

P = 0x800000000000000000000000000000000000000000000000000000000002ff7f
Q = (P - 1) // 2
G = pow(2, 2, P)
H = pow(3, 2, P)

def _poly(coeffs, x):
    r = 0
    for c in reversed(coeffs):
        r = (r * x + c) % Q
    return r

def deal(secret, blind, t, n, a_coeffs, b_coeffs):
    fc = [secret % Q] + [c % Q for c in a_coeffs[:t - 1]]
    bc = [blind % Q] + [c % Q for c in b_coeffs[:t - 1]]
    shares = [(i, _poly(fc, i), _poly(bc, i)) for i in range(1, n + 1)]
    commits = [(pow(G, fc[j], P) * pow(H, bc[j], P)) % P for j in range(t)]
    return shares, commits

def verify_share(share, commits):
    i, y, z = share
    lhs = (pow(G, y, P) * pow(H, z, P)) % P
    rhs = 1
    for j, c in enumerate(commits):
        rhs = (rhs * pow(c, pow(i, j, Q), P)) % P
    return lhs == rhs

def reconstruct(shares):
    s = 0
    for a, (xi, yi, _) in enumerate(shares):
        num, den = 1, 1
        for b, (xj, _, _) in enumerate(shares):
            if a == b:
                continue
            num = (num * (-xj)) % Q
            den = (den * (xi - xj)) % Q
        s = (s + yi * num * pow(den, -1, Q)) % Q
    return s % Q

if __name__ == "__main__":
    secret = 0xC0FFEE1234567890FEDCBA9876543210DEADBEEFCAFEBABE1029384756AB
    blind = 0x5EED0000000000000000000000000000000000000000000000000000BEEF
    T, N = 3, 5
    ac = [0x1111111111111111111111111111111111111111111111111111111111,
          0x2222222222222222222222222222222222222222222222222222222222]
    bc = [0x3333333333333333333333333333333333333333333333333333333333,
          0x4444444444444444444444444444444444444444444444444444444444]
    shares, commits = deal(secret, blind, T, N, ac, bc)
    for j, c in enumerate(commits):
        print("REF commit_%d %064x" % (j, c))
    for (i, y, z) in shares:
        print("REF share_%d %064x %064x" % (i, y, z))
    all_ok = all(verify_share(s, commits) for s in shares)
    print("REF all_shares_verify " + ("YES" if all_ok else "NO"))
    i, y, z = shares[2]
    print("REF tampered_f_rejected " + ("YES" if not verify_share((i, y ^ 1, z), commits) else "NO"))
    print("REF tampered_b_rejected " + ("YES" if not verify_share((i, y, z ^ 1), commits) else "NO"))
    rec = reconstruct([shares[0], shares[2], shares[4]])
    print("REF reconstruct_t " + ("YES" if rec == secret % Q else "NO"))
    print("REF below_threshold_wrong " + ("YES" if reconstruct(shares[:2]) != secret % Q else "NO"))
    sys.exit(0 if all_ok and rec == secret % Q else 1)
