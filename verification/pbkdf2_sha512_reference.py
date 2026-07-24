#!/usr/bin/env python3
"""Third-party oracle for the shipping PBKDF2-HMAC-SHA512 (`derive_key_sha512`).

Deliberately NOT a from-scratch reimplementation. The point of the anchor audit (see
docs/VERIFICATION-ANCHORS.md) is that a twin we write ourselves can agree with our C for the same wrong
reason -- that is exactly how the ristretto255 hash-to-group defect at step [94] stayed hidden. So this
oracle calls hashlib.pbkdf2_hmac, i.e. OpenSSL: an independent, widely-deployed, separately-audited
implementation that cannot share our misreading of the spec. Same role libsodium plays for ristretto255.

Emits REF lines byte-identical in form to pbkdf2_sha512_vectors.c so the suite step can diff them.
"""
import hashlib

CASES = [
    ("password", "salt", 1, 64),
    ("password", "salt", 2, 64),
    ("password", "salt", 4096, 64),
    ("password", "salt", 4096, 100),
    ("password", "salt", 1, 32),
    ("password", "salt", 16, 200),
    ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 64),
    ("p", "s", 1, 64),
    ("", "salt", 1, 64),
    ("password", "", 1, 64),
]

for pwd, salt, iters, dklen in CASES:
    dk = hashlib.pbkdf2_hmac("sha512", pwd.encode(), salt.encode(), iters, dklen)
    print(f"REF {pwd}|{salt}|{iters}|{dklen}={dk.hex()}")
