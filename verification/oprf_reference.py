#!/usr/bin/env python3
"""
oprf_reference.py — independent reference for the OPRF password-hardening PoC (docs/OPRF-SPEC.md,
IDEAS-BACKLOG.md §C).

An Oblivious PRF (2HashDH / CFRG DH-OPRF) hardens a password against OFFLINE guessing: the derived key
depends on both the password AND a secret held by a rate-limited server, and the server learns neither
the password nor the output. A stolen disk cannot be brute-forced offline — each guess needs one online
query to the server, which can rate-limit or lock out. It composes with the Shamir factor (threshold
OPRF / PPSS across several servers so no single server is trusted).

  public:  prime p, prime order q, generator g of the order-q subgroup
  server:  secret k in [1,q-1]
  H2(pw) = g^( int(SHA256("h2"||pw)) mod q ) mod p          # hash password to a group element
  blind:  r in [1,q-1];  A = H2(pw)^r mod p                  # client -> server (blinded)
  eval:   B = A^k mod p                                       # server (sees only A)
  unblind:U = B^(r^-1 mod q) mod p = H2(pw)^k mod p           # client removes the blind
  output: F = SHA256("oprf" || pw || U)                       # the hardened key

Layer-1 independent reference (Python bigint + hashlib); oprf_poc.c drives the REAL in-tree Sha2.c.
build_and_verify.sh diffs the REF lines byte-for-byte.
"""

import hashlib

P = 17592186046427
Q = 8796093023213      # prime order of g
G = 4

def be64(b):  return int.from_bytes(b[:8], "big")
def le64(x):  return (x & ((1 << 64) - 1)).to_bytes(8, "little")

def Hq(pw):   return be64(hashlib.sha256(b"h2" + pw).digest()) % Q
def H2(pw):   return pow(G, Hq(pw), P)
def oprf_out(pw, U): return hashlib.sha256(b"oprf" + pw + le64(U)).digest()

def evaluate(pw, k, r):
    A = pow(H2(pw), r, P)            # client blinds
    B = pow(A, k, P)                 # server evaluates (sees only A)
    U = pow(B, pow(r, Q - 2, Q), P)  # client unblinds: B^(1/r) = H2(pw)^k
    return A, oprf_out(pw, U)

PW = b"correct horse battery staple"
K  = 0x0123456789ABC % Q
R1 = 0xABCDEF123456 % Q
R2 = 0x0F1E2D3C4B5A % Q
K_WRONG = 0x9999999999 % Q

def main():
    A1, F1 = evaluate(PW, K, R1)
    print("REF oprf_output = " + F1.hex())

    A2, F2 = evaluate(PW, K, R2)
    print("REF output independent of blind (F(r1)==F(r2)) = " + ("YES" if F1 == F2 else "NO"))
    print("REF blinded messages differ (A(r1)!=A(r2)) = " + ("YES" if A1 != A2 else "NO"))
    # the server sees A, never the password's group element H2(pw)
    print("REF server sees blinded A != H2(pw) = " + ("YES" if A1 != H2(PW) else "NO"))
    # offline resistance: without the server key k the output cannot be computed
    _, Fwrong = evaluate(PW, K_WRONG, R1)
    print("REF wrong server key -> different output = " + ("YES" if Fwrong != F1 else "NO"))
    # different password -> different output
    _, Fpw = evaluate(b"correct horse battery stapl3", K, R1)
    print("REF different password -> different output = " + ("YES" if Fpw != F1 else "NO"))

if __name__ == "__main__":
    main()
