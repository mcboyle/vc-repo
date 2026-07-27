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


# ---------------------------------------------------------------------------------------------
# Mount-path partition (anti-coercion-oracle), derived INDEPENDENTLY of VcStatus.c.
#
# The rule, stated from the threat model rather than transcribed from the C: a status collapses iff
# an adversary could learn it BY TRYING PASSPHRASES. Everything else passes through, because hiding
# it costs diagnosability and buys no secrecy.
#
# VC_ERR_TAMPERED is deliberately NOT collapsed: it reports that the medium was modified -- which
# whoever modified it already knows -- and it is not learned by guessing. Collapsing it would undo
# the fork's shipped tamper-evidence for nothing.
CREDENTIAL_DEPENDENT = {
    "wrong_password",   # the adversary is guessing; this is the answer they already expect
    "factor_missing",   # reveals that a hardware/threshold factor is configured
    "slot_expired",     # KEYSLOT-POLICY-DESIGN.md requires expiry to be SILENT
    "slot_locked",      # reveals that per-slot attempt policy exists
    "duress",           # DURESS-DISMOUNT-SPEC.md requires indistinguishability from a failure
}
COLLAPSE_TO = "wrong_password"   # what stock VeraCrypt already says for a failed mount


def mount_safe(name):
    return COLLAPSE_TO if name in CREDENTIAL_DEPENDENT else name


if __name__ == "__main__":
    import sys
    if "--mountsafe" in sys.argv:
        # index:index pairs in enum order, matching the C harness's MOUNTSAFE line. Built from
        # CONTRACT (this file's own pin) so the mapping is re-derived here, not transcribed from C.
        order = [n for n, _ in CONTRACT]
        idx = {n: i for i, n in enumerate(order)}
        print("MOUNTSAFE " + " ".join("%d:%d" % (i, idx[mount_safe(n)]) for i, n in enumerate(order)))
