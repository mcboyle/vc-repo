#!/usr/bin/env python3
# Independent reference for per-sector authentication (docs/PERSECTOR-AUTH-SPEC.md,
# IDEAS-BACKLOG.md A). dm-integrity-style: one MAC tag per sector, stored in a
# separate tag area, over the sector CIPHERTEXT (encrypt-then-MAC) and BOUND to
# the sector index so a valid (ciphertext, tag) pair cannot be relocated.
#
#   tag_i = keyed_BLAKE3(K_mac, le64(sector_index) || ciphertext_i)[0..16]   # 128-bit tag
#
# A PRF, not a one-time MAC (research batch-2 item C2). The prior construction
# (otk_i = ChaCha20(mac_key, le64(index)); tag_i = Poly1305(otk_i, ct_i)) reused
# the same one-time Poly1305 key on every REWRITE of a sector, which a two-snapshot
# adversary breaks. keyed BLAKE3 degrades gracefully under key reuse. le64(index)
# stays inside the PRF input (relocation resistance). Reuses the independent
# BLAKE3 from blake3_reference.py (step [27]); persector_poc.c drives the real
# in-tree BLAKE3. REF lines diffed byte-for-byte.
import sys
from blake3_reference import blake3_keyed

SECTOR = 64
N = 8
TAGLEN = 16

def le64(x):
    return x.to_bytes(8, 'little')

def sector_tag(kmac, index, ciphertext):
    return blake3_keyed(le64(index) + ciphertext, kmac, TAGLEN)

def verify(kmac, index, ciphertext, tag):
    return sector_tag(kmac, index, ciphertext) == tag

def make_ciphertext():
    return [bytes((i * 53 + j * 7 + 1) & 0xff for j in range(SECTOR)) for i in range(N)]

if __name__ == "__main__":
    kmac = bytes((0x40 + i) & 0xff for i in range(32))
    ct = make_ciphertext()
    tags = [sector_tag(kmac, i, ct[i]) for i in range(N)]
    for i in range(N):
        print("REF tag_%d %s" % (i, tags[i].hex()))

    # (1) all sectors verify
    print("REF accept_all " + ("YES" if all(verify(kmac, i, ct[i], tags[i]) for i in range(N)) else "NO"))

    # (2) per-sector independence: tamper sector 5 -> only sector 5 fails
    t = list(ct); t[5] = bytes([t[5][0] ^ 0x01]) + t[5][1:]
    fail5 = not verify(kmac, 5, t[5], tags[5])
    others_ok = all(verify(kmac, i, ct[i], tags[i]) for i in range(N) if i != 5)
    print("REF tamper_only_5_fails " + ("YES" if (fail5 and others_ok) else "NO"))

    # (3) relocation: swap the (ciphertext, tag) of sectors 3 and 5; verify at their
    # NEW positions (le64(index) inside the PRF input) -> both rejected
    reloc_5 = verify(kmac, 5, ct[3], tags[3])   # sector 3's data+tag now at slot 5
    reloc_3 = verify(kmac, 3, ct[5], tags[5])   # sector 5's data+tag now at slot 3
    print("REF relocation_detected " + ("YES" if (not reloc_5 and not reloc_3) else "NO"))

    # (4) wrong master key -> tag differs
    wk = bytearray(kmac); wk[0] ^= 0x01
    print("REF wrongkey_detected " + ("YES" if not verify(bytes(wk), 0, ct[0], tags[0]) else "NO"))

    # (5) NEW — rewrite/key-reuse safety (the property the one-time Poly1305 construction FAILED):
    # two rewrites of the SAME sector under the SAME K_mac produce INDEPENDENT tags; each verifies
    # only its own content and neither forges the other. No (r,s) one-time key exists to recover.
    v1 = bytes((j * 3 + 11) & 0xff for j in range(SECTOR))
    v2 = bytes((j * 5 + 200) & 0xff for j in range(SECTOR))
    tg1 = sector_tag(kmac, 5, v1)
    tg2 = sector_tag(kmac, 5, v2)
    diff = tg1 != tg2
    v1ok = verify(kmac, 5, v1, tg1)
    v2ok = verify(kmac, 5, v2, tg2)
    cross1 = not verify(kmac, 5, v2, tg1)
    cross2 = not verify(kmac, 5, v1, tg2)
    print("REF rewrite_reuse_safe " + ("YES" if (diff and v1ok and v2ok and cross1 and cross2) else "NO"))
