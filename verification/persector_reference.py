#!/usr/bin/env python3
# Independent reference for per-sector authentication (docs/PERSECTOR-AUTH-SPEC.md,
# IDEAS-BACKLOG.md A). dm-integrity-style: one MAC tag per sector, stored in a
# separate tag area, over the sector CIPHERTEXT (encrypt-then-MAC) and BOUND to
# the sector index so a valid (ciphertext, tag) pair cannot be relocated.
#
#   nonce_i = le64(sector_index)                 # distinct per sector
#   otk_i   = ChaCha20(sector_mac_key, nonce_i)[0..32]
#   tag_i   = Poly1305(otk_i, ciphertext_i)
#
# nonce = index gives every sector its own one-time Poly1305 key, so tags are
# independent AND relocation-resistant (swapping two sectors' ciphertext+tag
# yields the wrong otk on both). Reuses the step-18/step-20 building blocks;
# persector_poc.c drives the real in-tree objects. REF lines diffed byte-for-byte.
import sys
from keyslot_mac_reference import chacha20_block
from poly1305_reference import poly1305_mac

SECTOR = 64
N = 8

def le64(x):
    return x.to_bytes(8, 'little')

def otk(sector_mac_key, index):
    return chacha20_block(sector_mac_key, 0, le64(index), 20)[:32]

def sector_tag(sector_mac_key, index, ciphertext):
    return poly1305_mac(ciphertext, otk(sector_mac_key, index))

def verify(sector_mac_key, index, ciphertext, tag):
    return sector_tag(sector_mac_key, index, ciphertext) == tag

def make_ciphertext():
    return [bytes((i * 53 + j * 7 + 1) & 0xff for j in range(SECTOR)) for i in range(N)]

if __name__ == "__main__":
    smk = bytes((0x40 + i) & 0xff for i in range(32))
    ct = make_ciphertext()
    tags = [sector_tag(smk, i, ct[i]) for i in range(N)]
    for i in range(N):
        print("REF tag_%d %s" % (i, tags[i].hex()))

    # all sectors verify
    print("REF accept_all " + ("YES" if all(verify(smk, i, ct[i], tags[i]) for i in range(N)) else "NO"))

    # tamper sector 5 -> only sector 5 fails (per-sector independence)
    t = list(ct); t[5] = bytes([t[5][0] ^ 0x01]) + t[5][1:]
    fail5 = not verify(smk, 5, t[5], tags[5])
    others_ok = all(verify(smk, i, ct[i], tags[i]) for i in range(N) if i != 5)
    print("REF tamper_only_5_fails " + ("YES" if (fail5 and others_ok) else "NO"))

    # relocation: swap the (ciphertext, tag) of sectors 3 and 5; verify at their
    # NEW positions (nonce = new index) -> both rejected
    reloc_5 = verify(smk, 5, ct[3], tags[3])   # sector 3's data+tag now at slot 5
    reloc_3 = verify(smk, 3, ct[5], tags[5])   # sector 5's data+tag now at slot 3
    print("REF relocation_detected " + ("YES" if (not reloc_5 and not reloc_3) else "NO"))

    # wrong master key -> tag differs
    wk = bytearray(smk); wk[0] ^= 0x01
    print("REF wrongkey_detected " + ("YES" if not verify(bytes(wk), 0, ct[0], tags[0]) else "NO"))
