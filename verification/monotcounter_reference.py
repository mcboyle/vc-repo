#!/usr/bin/env python3
# Independent reference for rollback/replay protection via a monotonic counter
# (docs/ROLLBACK-COUNTER-SPEC.md, IDEAS-BACKLOG.md A). Merkle roots and per-sector
# MACs detect *modification* but not *replay* of a whole older-but-internally-
# consistent snapshot. A counter held in tamper-resistant hardware (TPM NV /
# token / secure element) that only ever increments closes that: bind its value
# into the top-level "commit" authenticator, so an old snapshot carries an old
# counter and fails to verify against the advanced hardware counter.
#
#   otk_c = ChaCha20(commit_key, le64(counter))[0..32]   # counter is monotonic ->
#   tag   = Poly1305(otk_c, state_root)                  #   otk never repeats
#   verify at mount: read counter C from hardware; recompute tag over the stored
#   state_root with C; accept iff it matches AND the on-disk counter == C.
#
# Reuses the step-18/step-20 building blocks; monotcounter_poc.c drives the real
# in-tree objects. REF lines are diffed byte-for-byte by build_and_verify.sh.
import sys
from keyslot_mac_reference import chacha20_block
from poly1305_reference import poly1305_mac

NVER = 4

def le64(x):
    return x.to_bytes(8, 'little')

def commit_tag(commit_key, counter, state_root):
    otk = chacha20_block(commit_key, 0, le64(counter), 20)[:32]
    return poly1305_mac(state_root, otk)

def verify(commit_key, hw_counter, disk_counter, state_root, tag):
    # both the binding AND the plain counter-equality must hold
    if disk_counter != hw_counter:
        return False
    return commit_tag(commit_key, hw_counter, state_root) == tag


class NvCounter:
    """Models a TPM-NV / secure-element monotonic counter: increment-only; a
    request to set any value <= current is refused (this is the hardware property
    the whole scheme rests on)."""
    def __init__(self):
        self.value = 0
    def increment(self):
        self.value += 1
        return self.value
    def try_set(self, v):
        if v <= self.value:
            return False   # refused: never goes backward
        self.value = v
        return True


def state_root(version):
    # stand-in for the Merkle root of version `version` (32 bytes, deterministic)
    return bytes(((version * 97 + i * 13 + 5) & 0xff) for i in range(32))

if __name__ == "__main__":
    ck = bytes((0x20 + i) & 0xff for i in range(32))

    # commit a sequence of versions v0..v3, each incrementing the hw counter
    nv = NvCounter()
    commits = []   # (counter, state_root, tag) as stored on disk per version
    for v in range(NVER):
        c = nv.value            # commit binds the CURRENT counter value
        sr = state_root(v)
        tag = commit_tag(ck, c, sr)
        commits.append((c, sr, tag))
        print("REF commit_tag_%d %s" % (v, tag.hex()))
        nv.increment()          # advance for the next commit

    # after the sequence the hardware counter sits at NVER (=4); the live version
    # is v3 committed at counter 3. Roll the hardware back to match a live mount:
    # a genuine mount reads the counter that the LIVE version was committed under.

    # fresh accept: each version verifies at its own counter
    fresh = all(verify(ck, c, c, sr, tag) for (c, sr, tag) in commits)
    print("REF fresh_accept " + ("YES" if fresh else "NO"))

    # rollback attack: attacker restores the whole v1 snapshot (counter 1) but the
    # hardware counter has since advanced to 3 (user committed v2, v3). Mount reads
    # hw=3; the restored disk carries counter 1 -> rejected.
    c1, sr1, tag1 = commits[1]
    rolled_back_ok = verify(ck, 3, c1, sr1, tag1)
    print("REF rollback_detected " + ("YES" if not rolled_back_ok else "NO"))

    # even if the attacker forges the on-disk counter marker to 3, tag1 was bound
    # to counter 1, so recomputing under 3 still fails.
    forged_ok = verify(ck, 3, 3, sr1, tag1)
    print("REF forged_marker_detected " + ("YES" if not forged_ok else "NO"))

    # tamper: modify the live state_root but keep its tag -> rejected at its counter
    c3, sr3, tag3 = commits[3]
    sr3_t = bytes([sr3[0] ^ 0x01]) + sr3[1:]
    print("REF tamper_state_detected " + ("YES" if not verify(ck, c3, c3, sr3_t, tag3) else "NO"))

    # monotonicity: the modeled NV counter refuses to go backward or sideways
    mono = (nv.try_set(nv.value) is False) and (nv.try_set(nv.value - 1) is False) and (nv.try_set(nv.value + 5) is True)
    print("REF monotonic_enforced " + ("YES" if mono else "NO"))

    # wrong commit key -> tag differs
    wk = bytearray(ck); wk[0] ^= 0x01
    print("REF wrongkey_detected " + ("YES" if not verify(bytes(wk), c3, c3, sr3, tag3) else "NO"))
