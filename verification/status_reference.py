#!/usr/bin/env python3
# status_reference.py — independent pin of the VcStatus exit-code contract (ROI item 47).
# Order matches the VcStatus enum. If VcStatus.c is renumbered, the byte-for-byte diff in
# build_and_verify.sh breaks — that is the stability guarantee's teeth.
CONTRACT = [
    ("ok",             0),
    ("param",          64),
    ("io",             74),
    ("wrong_password", 77),
    ("factor_missing", 69),
    ("slot_expired",   75),
    ("slot_locked",    76),
    ("duress",         78),
    ("tampered",       79),
    ("unsupported",    70),
    ("internal",       71),
]
for name, code in CONTRACT:
    print("REF %s %d" % (name, code))
