#!/usr/bin/env python3
# Independent reference for the v2 on-disk format's two NOVEL properties (docs/V2-FORMAT-SPEC.md, T1-1):
#   A. mode discrimination with NOTHING stored, via a per-mode domain-separated MAC key over ciphertext;
#   B. full-volume MAC-table indistinguishability (free slots = keystream; hidden-overwrite reads as free).
# Reuses the independent pure-python BLAKE3 (blake3_reference.py, step [27]); v2format_poc.c drives the
# real in-tree BLAKE3. Every REF line is diffed byte-for-byte against the C harness.
from blake3_reference import blake3_keyed

TAGLEN = 16
SECTOR = 64
NSEC   = 512
NWRIT  = 128

def le64(x):
    return x.to_bytes(8, 'little')

def kdf(master, label, outlen):        # subkey = keyed-BLAKE3(master, ascii-label)
    return blake3_keyed(label.encode('ascii'), master, outlen)

def prg(key, counter, outlen):         # keystream = keyed-BLAKE3(key, le64(counter))
    return blake3_keyed(le64(counter), key, outlen)

def sector_tag(kmac, index, ct):       # tag = keyed-BLAKE3(K_mac, le64(index) || ciphertext)[0..16]
    return blake3_keyed(le64(index) + ct, kmac, TAGLEN)

def verify(kmac, index, ct, tag):
    return sector_tag(kmac, index, ct) == tag

if __name__ == "__main__":
    master = bytes((0x40 + i) & 0xff for i in range(32))
    kmac_h    = kdf(master, "VeraCrypt/v2/mac/hctr2",    32)
    kmac_a    = kdf(master, "VeraCrypt/v2/mac/adiantum", 32)
    kenc_h    = kdf(master, "VeraCrypt/v2/enc/hctr2",    32)
    kfree     = kdf(master, "VeraCrypt/v2/tablefree",    32)
    kfreedata = kdf(master, "VeraCrypt/v2/freedata",     32)
    khidden   = kdf(master, "VeraCrypt/v2/hidden",       32)

    # [A] mode discrimination
    ct0  = prg(kenc_h, 0, SECTOR)
    tag0 = sector_tag(kmac_h, 0, ct0)
    print("REF kmac_hctr2 " + kmac_h.hex())
    print("REF tag0 " + tag0.hex())
    as_h = verify(kmac_h, 0, ct0, tag0)
    as_a = verify(kmac_a, 0, ct0, tag0)
    print("REF discriminate " + ("YES" if (as_h and not as_a) else "NO"))
    v1slot = prg(kenc_h, 0xdead, TAGLEN)
    print("REF v1_fallthrough " + ("YES" if (not verify(kmac_h, 0, ct0, v1slot)
                                             and not verify(kmac_a, 0, ct0, v1slot)) else "NO"))

    # [B] full-volume MAC table
    table = [None] * NSEC
    written_ct = [None] * NWRIT
    for i in range(NSEC):
        if i < NWRIT:
            written_ct[i] = prg(kenc_h, 1000 + i, SECTOR)
            table[i] = sector_tag(kmac_h, i, written_ct[i])
        else:
            table[i] = prg(kfree, i, TAGLEN)
    blob = b"".join(table)
    print("REF table_hash " + blake3_keyed(blob, master, 32).hex())

    written_ok = all(verify(kmac_h, i, written_ct[i], table[i]) for i in range(NWRIT))
    print("REF written_verify " + ("YES" if written_ok else "NO"))

    free_reads_free = all(not verify(kmac_h, i, prg(kfreedata, i, SECTOR), table[i])
                          for i in range(NWRIT, NSEC))
    print("REF free_reads_as_free " + ("YES" if free_reads_free else "NO"))

    hidden_reads_free = all(not verify(kmac_h, i, prg(khidden, i, SECTOR), table[i])
                            for i in range(NWRIT, NSEC))
    print("REF hidden_reads_as_free " + ("YES" if hidden_reads_free else "NO"))

    # chi-square over 256 bins (same order as the C harness; integer round for exact match)
    hist = [0] * 256
    total = 0
    for row in table:
        for byte in row:
            hist[byte] += 1
            total += 1
    expv = total / 256.0
    chisq = 0.0
    for b in range(256):
        d = hist[b] - expv
        chisq += d * d / expv
    print("REF table_chisq " + str(int(chisq + 0.5)))
