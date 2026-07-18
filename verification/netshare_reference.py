#!/usr/bin/env python3
"""
netshare_reference.py — independent reference for the network-bound share PoC.

Layer 1 of the two-way convention: the McCallum-Relyea algebra in Python's native big integers, and
SHA-256 from hashlib (independent of VeraCrypt's Sha2.c). build_and_verify.sh diffs the REF lines
against netshare_poc.c, which drives the REAL in-tree Sha2.c. The recovery identity holds in any
group, so this proves the protocol, not a parameter size.
"""

import hashlib

P = 2305843009213693921   # largest prime below 2^61 (non-Mersenne), matching netshare_poc.c
G = 3

S_SECRET = 1234567890123456789
C_EPH    = 1111111111111111111
E_EPH    = 999999999999999999
E_EPH2   = 424242424242424242
S_WRONG  = 5555555555555555555

def powmod(b, e): return pow(b, e, P)
def mul(a, b):    return (a * b) % P
def inv(a):       return pow(a, P - 2, P)

def share_of(K):
    return hashlib.sha256(K.to_bytes(8, "little")).digest()

def mr_recover(S_pub, C_pub, s_server, e):
    X = mul(C_pub, powmod(G, e))       # client blinds
    Y = powmod(X, s_server)            # server
    return mul(Y, inv(powmod(S_pub, e)))  # client unblinds

def main():
    S = powmod(G, S_SECRET)
    C = powmod(G, C_EPH)
    Kprov = powmod(S, C_EPH)
    X = mul(C, powmod(G, E_EPH))
    Y = powmod(X, S_SECRET)
    Krec = mr_recover(S, C, S_SECRET, E_EPH)

    print("REF S = %020d" % S)
    print("REF C = %020d" % C)
    print("REF Kprov = %020d" % Kprov)
    print("REF X = %020d" % X)
    print("REF Y = %020d" % Y)
    print("REF Krec = %020d" % Krec)
    print("REF share = " + share_of(Kprov).hex())

if __name__ == "__main__":
    main()
