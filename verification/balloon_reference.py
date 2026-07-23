#!/usr/bin/env python3
"""
balloon_reference.py — independent reference for the Balloon memory-hard KDF PoC
(docs/BALLOON-SPEC.md, IDEAS-BACKLOG.md §C).

Balloon hashing (Boneh, Corrigan-Gibbs, Schechter 2016) is a provably memory-hard password hash built
on a *standard* cryptographic hash — here VeraCrypt's in-tree SHA-256. It is a candidate to sit
alongside Argon2id in the KDF seam: "slow by design", with an explicit space cost (number of blocks)
and time cost (rounds), and no dependence on a bespoke permutation.

Single-lane Balloon:
  n = s_cost blocks of one digest each; cnt = monotonic counter; delta = 3 dependencies/block.
  Expand:  buf[0] = H(cnt++ || password || salt);  buf[m] = H(cnt++ || buf[m-1])
  Mix (t_cost rounds): for each m:
     buf[m] = H(cnt++ || buf[(m-1) mod n] || buf[m])
     for i in 0..delta-1:
        idx    = H(cnt++ || t || m || i || salt);  other = int(idx) mod n
        buf[m] = H(cnt++ || buf[m] || buf[other])
  Extract: buf[n-1]
All integers are 8-byte little-endian. Layer-1 independent reference (hashlib); balloon_poc.c drives
the REAL in-tree Sha2.c. build_and_verify.sh diffs the REF lines byte-for-byte.
"""

import hashlib

DIGEST = 32
DELTA = 3

def le64(x):
    return (x & ((1 << 64) - 1)).to_bytes(8, "little")

def H(*parts):
    return hashlib.sha256(b"".join(parts)).digest()

def balloon(password, salt, s_cost, t_cost):
    n = s_cost
    buf = [b""] * n
    cnt = 0
    # Expand
    buf[0] = H(le64(cnt), password, salt); cnt += 1
    for m in range(1, n):
        buf[m] = H(le64(cnt), buf[m-1]); cnt += 1
    # Mix
    for t in range(t_cost):
        for m in range(n):
            prev = buf[(m - 1) % n]
            buf[m] = H(le64(cnt), prev, buf[m]); cnt += 1
            for i in range(DELTA):
                idx = H(le64(cnt), le64(t), le64(m), le64(i), salt); cnt += 1
                other = int.from_bytes(idx[:8], "little") % n
                buf[m] = H(le64(cnt), buf[m], buf[other]); cnt += 1
    return buf[n-1]

def main():
    pw = b"correct horse battery staple"
    salt = bytes((i * 5 + 1) & 0xff for i in range(16))
    out = balloon(pw, salt, 16, 3)
    print("REF balloon(s=16,t=3) = " + out.hex())

    # determinism + dependence on inputs
    same = balloon(pw, salt, 16, 3) == out
    diff_salt = balloon(pw, bytes(16), 16, 3) != out
    diff_space = balloon(pw, salt, 32, 3) != out
    diff_time = balloon(pw, salt, 16, 5) != out
    print("REF deterministic (same inputs -> same output) = " + ("YES" if same else "NO"))
    print("REF different salt -> different output = " + ("YES" if diff_salt else "NO"))
    print("REF different space cost -> different output = " + ("YES" if diff_space else "NO"))
    print("REF different time cost -> different output = " + ("YES" if diff_time else "NO"))

if __name__ == "__main__":
    main()
