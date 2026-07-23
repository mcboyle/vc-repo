#!/usr/bin/env python3
"""
balloon_prf_reference.py — independent reference for the shipping derive_key_balloon (step [38]).

Layer 1 of the two-way convention, diffed against balloon_prf_test.c (which drives the REAL compiled
Common/Pkcs5.c). Balloon (single lane, delta=3, over hashlib SHA-256) is reimplemented from the
algorithm, exactly as verification/balloon_reference.py did for the step-[16] PoC; before emitting
vectors, this script ASSERTS that its core reproduces the [16] anchor 635ebeac... for s=16,t=3, so
the shipping function is chained to the proven construction. The long-output expansion is
block_i = SHA-256(K || BE32(i) || salt), i = 1.., truncated to dklen.
"""

import hashlib
import struct
import sys

DIGEST = 32
DELTA = 3

STEP16_ANCHOR = "635ebeac846c8af30eb342e489dc7a5ec8a16a0ddf49959ae72291d9e92ec08d"


def le64(x):
    return struct.pack("<Q", x)


def balloon(pw, salt, s_cost, t_cost):
    """Balloon KDF, single lane, delta=3 (identical to balloon_reference.py's algorithm)."""
    cnt = 0
    buf = []
    h = hashlib.sha256(le64(cnt) + pw + salt).digest(); cnt += 1
    buf.append(h)
    for m in range(1, s_cost):
        buf.append(hashlib.sha256(le64(cnt) + buf[m - 1]).digest()); cnt += 1
    for t in range(t_cost):
        for m in range(s_cost):
            prev = buf[(m - 1) % s_cost]
            buf[m] = hashlib.sha256(le64(cnt) + prev + buf[m]).digest(); cnt += 1
            for i in range(DELTA):
                idx = hashlib.sha256(le64(cnt) + le64(t) + le64(m) + le64(i) + salt).digest(); cnt += 1
                other = int.from_bytes(idx[0:8], "little") % s_cost
                buf[m] = hashlib.sha256(le64(cnt) + buf[m] + buf[other]).digest(); cnt += 1
    return buf[s_cost - 1]


def derive_key_balloon(pw, salt, tcost, space_kib, dklen):
    n = space_kib * (1024 // DIGEST)
    K = balloon(pw, salt, n, tcost)
    if dklen <= DIGEST:
        return K[:dklen]
    out = bytearray()
    blk = 1
    while len(out) < dklen:
        out += hashlib.sha256(K + struct.pack(">I", blk) + salt).digest()
        blk += 1
    return bytes(out[:dklen])


def resolved_params(pim, override=(0, 0)):
    ot, os_ = override
    if ot != 0 and os_ != 0:
        return ot, os_
    if pim <= 0:
        return 3, 1024
    t = 3 + (pim - 1) // 5
    s = min(1024 + (pim - 1) * 512, 65536)
    return t, s


def main():
    pw = b"correct horse battery staple"
    salt = bytes((i * 5 + 1) & 0xFF for i in range(16))

    # chain to the proven step-[16] core before emitting anything
    core = balloon(pw, salt, 16, 3)
    if core.hex() != STEP16_ANCHOR:
        print("FATAL: python Balloon core does not reproduce the step-[16] anchor", file=sys.stderr)
        sys.exit(1)

    print("REF balloon dk32(skib=1,t=3) = " + derive_key_balloon(pw, salt, 3, 1, 32).hex())
    print("REF balloon dk64(skib=1,t=3) = " + derive_key_balloon(pw, salt, 3, 1, 64).hex())
    print("REF balloon dk192(skib=1,t=3) = " + derive_key_balloon(pw, salt, 3, 1, 192).hex())

    for pim in (0, 1, 13, 485):
        t, s = resolved_params(pim)
        print("REF balloon params pim=%d = %d,%d" % (pim, t, s))
    t, s = resolved_params(13, override=(7, 4096))
    print("REF balloon params override = %d,%d" % (t, s))


if __name__ == "__main__":
    main()
