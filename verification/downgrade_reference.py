#!/usr/bin/env python3
# Independent reference for header-version + anti-downgrade parameter binding
# (docs/ANTI-DOWNGRADE-SPEC.md, IDEAS-BACKLOG.md A). An attacker who can edit the
# header could claim WEAKER KDF/cipher parameters (tiny Argon2 memory, a weak PRF)
# hoping the victim's software re-derives under them, cheapening offline attack.
# Binding a canonical serialization of every negotiated parameter into a MAC
# (keyed from the password) makes any such edit produce a different tag -> the
# volume fails closed instead of silently accepting downgraded parameters.
#
# Canonical layout is FIXED-WIDTH big-endian (unambiguous; no field-boundary
# confusion): version:u16 | prf_id:u16 | cipher_id:u16 | mode_id:u16 |
# argon_mem_kib:u32 | argon_iters:u32 | argon_parallelism:u8.
#
# HMAC-SHA256 here is hashlib; downgrade_poc.c drives the REAL in-tree Sha2.c.
# build_and_verify.sh diffs the REF lines byte-for-byte.
import struct, hmac, hashlib, sys

def canon(p):
    return struct.pack(">HHHH I I B",
                       p["version"], p["prf_id"], p["cipher_id"], p["mode_id"],
                       p["argon_mem_kib"], p["argon_iters"], p["argon_parallelism"])

def binding_key(password, salt):
    # stand-in for the header key; the point under test is parameter binding, not
    # the KDF itself (proven separately). HMAC-SHA256(password, salt).
    return hmac.new(password, salt, hashlib.sha256).digest()

def param_tag(password, salt, p):
    return hmac.new(binding_key(password, salt), canon(p), hashlib.sha256).digest()

def verify(password, salt, p, tag):
    return hmac.compare_digest(param_tag(password, salt, p), tag)

# a strong baseline parameter set (RFC 9106 "first" class Argon2id, say)
BASE = dict(version=2, prf_id=3, cipher_id=1, mode_id=2,
            argon_mem_kib=1048576, argon_iters=3, argon_parallelism=4)

# each downgrade an attacker might attempt
DOWNGRADES = {
    "argon_mem":    dict(BASE, argon_mem_kib=8),       # 1 GiB -> 8 KiB
    "argon_iters":  dict(BASE, argon_iters=1),
    "argon_par":    dict(BASE, argon_parallelism=1),
    "prf_weaker":   dict(BASE, prf_id=0),
    "cipher_weaker":dict(BASE, cipher_id=0),
    "mode_weaker":  dict(BASE, mode_id=0),
    "version_roll": dict(BASE, version=1),
}

if __name__ == "__main__":
    pw = b"correct horse battery staple"
    salt = bytes(((i * 11 + 3) & 0xff) for i in range(64))

    tag = param_tag(pw, salt, BASE)
    print("REF param_tag " + tag.hex())
    print("REF canon_base " + canon(BASE).hex())

    print("REF accept_base " + ("YES" if verify(pw, salt, BASE, tag) else "NO"))

    all_detected = True
    for name, dp in DOWNGRADES.items():
        ok = verify(pw, salt, dp, tag)   # attacker presents downgraded params + the ORIGINAL tag
        detected = not ok
        all_detected = all_detected and detected
        print("REF detect_%s %s" % (name, "YES" if detected else "NO"))
    print("REF all_downgrades_detected " + ("YES" if all_detected else "NO"))

    # wrong password -> different binding key -> different tag
    print("REF wrongpw_detected " + ("YES" if not verify(b"wrong pass", salt, BASE, tag) else "NO"))

    # canonical-encoding unambiguity: two DISTINCT parameter sets must never share
    # a serialization. Fixed-width fields guarantee it; show a boundary-swap pair
    # (mem<->iters values swapped) yields distinct canon bytes.
    a = dict(BASE, argon_mem_kib=3, argon_iters=1048576)
    b = dict(BASE, argon_mem_kib=1048576, argon_iters=3)
    print("REF canon_unambiguous " + ("YES" if canon(a) != canon(b) else "NO"))
