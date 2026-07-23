#!/usr/bin/env python3
"""atomic_header_reference.py — independent reference for the atomic-header commit tag (ROI item 50).

Reads 'K <hex>', 'HEADER <hex>', 'GEN <int>', 'CTAG <hex>' from stdin, computes
commitTag = HMAC-SHA256(K, header || gen[8 big-endian]) independently, prints PYTAG and MATCH/MISMATCH
against the C module's tag. Byte-for-byte cross-check of the commit-tag layout.
"""
import sys, hmac, hashlib

def main():
    v = {}
    for line in sys.stdin:
        p = line.split()
        if len(p) == 2 and p[0] in ("K", "HEADER", "CTAG"):
            v[p[0]] = bytes.fromhex(p[1])
        elif len(p) == 2 and p[0] == "GEN":
            v["GEN"] = int(p[1])
    if not {"K", "HEADER", "GEN", "CTAG"} <= set(v):
        print("MISSING-INPUT"); return 1
    msg = v["HEADER"] + v["GEN"].to_bytes(8, "big")
    tag = hmac.new(v["K"], msg, hashlib.sha256).digest()
    print("PYTAG", tag.hex())
    if tag == v["CTAG"]:
        print("MATCH: independent python HMAC commit tag == real AtomicHeader.c"); return 0
    print("MISMATCH: commit tag differs from the C module"); return 1

if __name__ == "__main__":
    sys.exit(main())
