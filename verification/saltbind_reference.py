#!/usr/bin/env python3
"""
saltbind_reference.py — independent reference for RAW_SECRET salt-binding.

The bound response is HMAC-SHA256(key=secret, msg=salt). This reimplements it with Python's hmac +
hashlib (independent of VeraCrypt's Sha2.c). build_and_verify.sh diffs the "REF saltbound" line against
saltbind_test.c, which drives the REAL HardwareKeyFactor.c over the real in-tree SHA-256.
"""

import hmac, hashlib

SECRET_LEN = 32
SALT_LEN = 64

def main():
    secret = bytes((0x50 + i) & 0xff for i in range(SECRET_LEN))
    salt = bytes((i * 3 + 7) & 0xff for i in range(SALT_LEN))
    tag = hmac.new(secret, salt, hashlib.sha256).digest()
    print("REF saltbound = " + tag.hex())

if __name__ == "__main__":
    main()
