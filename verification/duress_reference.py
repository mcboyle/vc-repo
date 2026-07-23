#!/usr/bin/env python3
"""
duress_reference.py — independent reference for the duress-passphrase token.

Layer 1 of the two-way convention: an independent HMAC-SHA256 (the ipad/opad construction built by
hand on Python's hashlib.sha256), matching tag = HMAC-SHA256(salt, passphrase). build_and_verify.sh
diffs the "REF" line here against duress_selftest.c, which drives VeraCrypt's real compiled
hmac_sha256. A byte-for-byte match proves the C integration computes the specified HMAC.
"""

import hashlib

SALT_LEN = 16
PASS = b"correct horse battery staple"

def salt_bytes():
    return bytes((i * 7 + 3) & 0xff for i in range(SALT_LEN))

def hmac_sha256(key, msg):
    block = 64  # SHA-256 block size
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key + b"\x00" * (block - len(key))
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5c for k in key)
    inner = hashlib.sha256(ipad + msg).digest()
    return hashlib.sha256(opad + inner).digest()

def main():
    tag = hmac_sha256(salt_bytes(), PASS)
    print("REF duress_tag = " + tag.hex())

if __name__ == "__main__":
    main()
