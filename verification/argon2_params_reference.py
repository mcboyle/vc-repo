#!/usr/bin/env python3
"""
argon2_params_reference.py — independent reference for the Argon2id parameter resolver.

The Argon2 algorithm is anchored to the published RFC 9106 vector inside argon2_params_test.c (the C
harness). This file independently reimplements only the part I wrote: the PIM->(iterations, memory,
parallelism) formula and the override selection. build_and_verify.sh diffs the "REF resolve ..." lines
against the harness driving the REAL in-tree Pkcs5.c.
"""

def get_argon2_params(pim):
    # mirrors get_argon2_params() in Common/Pkcs5.c
    if pim < 0:
        pim = 0
    if pim == 0:
        pim = 12
    m_mib = 64 + (pim - 1) * 32
    if m_mib > 1024:
        m_mib = 1024
    memcost_kib = m_mib * 1024
    if pim <= 31:
        iters = 3 + ((pim - 1) // 3)
    else:
        iters = 13 + (pim - 31)
    return iters, memcost_kib

def resolve(pim, override=None):
    if override is not None:
        m, t, p = override            # (memCostKiB, iterations, parallelism)
        return 1, t, m, p
    it, mc = get_argon2_params(pim)
    return 0, it, mc, 1

def main():
    for pim in [0, 1, 3, 12, 31, 32, 40]:
        used, t, m, p = resolve(pim)
        print("REF resolve pim=%d used=%d t=%u m=%u p=%u" % (pim, used, t, m, p))
    used, t, m, p = resolve(12, override=(262144, 5, 8))
    print("REF resolve pim=12 used=%d t=%u m=%u p=%u" % (used, t, m, p))

if __name__ == "__main__":
    main()
