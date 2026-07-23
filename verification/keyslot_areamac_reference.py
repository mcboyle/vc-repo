#!/usr/bin/env python3
"""keyslot_areamac_reference.py — independent reference for the keyslot-area MAC (ROI item 42).

Reads three lines from stdin: 'VMK <hex>', 'REGION <hex>', 'CTAG <hex>' (the C module's tag). Derives
K_area = HKDF-SHA256(VMK, salt=<empty>, info="keyslot-area-mac"), counts occupied "VCKS" slots in the
region at 1024-byte strides, computes the area tag independently, and prints PYTAG plus MATCH/MISMATCH
against the C tag. This is the byte-for-byte cross-check of both HKDF and the HMAC area construction.
"""
import sys, hmac, hashlib

STRIDE = 1024
MAGIC = b"VCKSAREA1"

def hkdf_sha256(ikm, info, length=32, salt=b"\x00"*32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def count_slots(region):
    n = 0
    off = 0
    while off + STRIDE <= len(region):
        if region[off:off+4] == b"VCKS":
            n += 1
        off += STRIDE
    return n

def area_tag(vmk, region):
    k_area = hkdf_sha256(vmk, b"keyslot-area-mac")
    slots = count_slots(region)
    msg = MAGIC + slots.to_bytes(4, "big") + region
    return hmac.new(k_area, msg, hashlib.sha256).digest()

def main():
    vals = {}
    for line in sys.stdin:
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("VMK", "REGION", "CTAG"):
            vals[parts[0]] = bytes.fromhex(parts[1])
    if not {"VMK", "REGION", "CTAG"} <= set(vals):
        print("MISSING-INPUT"); return 1
    tag = area_tag(vals["VMK"], vals["REGION"])
    print("PYTAG", tag.hex())
    if tag == vals["CTAG"]:
        print("MATCH: independent python HKDF+HMAC area tag == real KeyslotAreaMac.c")
        return 0
    print("MISMATCH: area tag differs from the C module"); return 1

if __name__ == "__main__":
    sys.exit(main())
