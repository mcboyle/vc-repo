#!/usr/bin/env python3
"""hkf_saltdefault_reference.py — independent reference for salt-binding-by-default (addendum Rec 1).

Reads 'SECRET <hex>' and 'SALT <hex>' from stdin and prints the salt-bound response
SBIND = HMAC-SHA256(key=secret, msg=salt) that a RAW_SECRET factor must produce once salt-binding is
on. The C harness prints the response its real HKFComputeResponse returned for the default-on config;
the suite diffs the two.
"""
import sys, hmac, hashlib

def main():
    v = {}
    for line in sys.stdin:
        p = line.split()
        if len(p) == 2 and p[0] in ("SECRET", "SALT"):
            v[p[0]] = bytes.fromhex(p[1])
    if not {"SECRET", "SALT"} <= set(v):
        print("MISSING-INPUT"); return 1
    tag = hmac.new(v["SECRET"], v["SALT"], hashlib.sha256).digest()
    print("SBIND", tag.hex())
    return 0

if __name__ == "__main__":
    sys.exit(main())
