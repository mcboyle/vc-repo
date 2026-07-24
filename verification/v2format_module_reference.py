#!/usr/bin/env python3
# Independent reference for the SHIPPING v2-format module (src/Common/V2Format.c, T1-1). The module uses
# HMAC-SHA256 over the in-tree Crypto/Sha2.c as its PRF; this reference uses hashlib/hmac independently.
# Every REF line is diffed byte-for-byte against v2format_module_test.c (which drives the real Sha2 object).
import hmac, hashlib

KEY_LEN = 32
TAG_LEN = 16
SECTOR  = 64

def le64(x):
    return x.to_bytes(8, 'little')

def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def mode_label(mode):
    return {0: "VeraCrypt/v2/mac/hctr2", 1: "VeraCrypt/v2/mac/adiantum"}[mode]

def derive_mode_key(master, mode):
    return hmac_sha256(master, mode_label(mode).encode('ascii'))[:KEY_LEN]

def sector_tag(macKey, index, ct):
    return hmac_sha256(macKey, le64(index) + ct)[:TAG_LEN]

def verify(macKey, index, ct, tag):
    return sector_tag(macKey, index, ct) == tag

def discover_mode(master, ct0, stored_tag):
    found = -1
    for mode in (0, 1):
        if verify(derive_mode_key(master, mode), 0, ct0, stored_tag):
            found = mode
    return found

def mactable_bytes(data_sectors, sector_size):
    ss = sector_size or 512
    raw = data_sectors * TAG_LEN
    return ((raw + ss - 1) // ss) * ss

def split_data_area(total_bytes, sector_size):
    ss = sector_size or 512
    if total_bytes < 2 * ss:
        return None
    total_sectors = total_bytes // ss
    usable = total_sectors
    while usable > 0:
        tbl = (usable * TAG_LEN + ss - 1) // ss
        if usable + tbl <= total_sectors:
            break
        usable -= 1
    if usable == 0:
        return None
    usable_bytes = usable * ss
    return usable_bytes, usable_bytes   # (usable, table offset == usable)

if __name__ == "__main__":
    master  = bytes((0x40 + i) & 0xff for i in range(32))
    ct0     = bytes((i * 7 + 3) & 0xff for i in range(SECTOR))
    kmac_h  = derive_mode_key(master, 0)
    kmac_a  = derive_mode_key(master, 1)
    tag0    = sector_tag(kmac_h, 0, ct0)

    print("REF kmac_hctr2 " + kmac_h.hex())
    print("REF kmac_adiantum " + kmac_a.hex())
    print("REF tag0 " + tag0.hex())
    print("REF discover_hctr2 %d" % discover_mode(master, ct0, tag0))
    master2 = bytearray(master); master2[0] ^= 0x01
    print("REF discover_wrongkey %d" % discover_mode(bytes(master2), ct0, tag0))
    print("REF discover_v1 %d" % discover_mode(master, ct0, b"\xAA" * TAG_LEN))

    print("REF mactable_1000_512 %d" % mactable_bytes(1000, 512))
    usable, off = split_data_area(1000 * 512, 512)
    print("REF split_512000_512 %d %d" % (usable, off))
    print("REF slot_5 %d" % (5 * TAG_LEN))
