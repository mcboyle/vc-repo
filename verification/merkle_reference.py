#!/usr/bin/env python3
# Independent Merkle-tree reference (docs/MERKLE-SPEC.md, IDEAS-BACKLOG.md A).
# A binary hash tree over the volume's sectors whose ROOT is held off-disk
# (header / hardware token / TPM NV). Any offline modification of any sector
# changes the root, so a trusted root detects tampering the XTS layer cannot.
#
# Domain separation follows RFC 6962 (Certificate Transparency) so a leaf can
# never be reinterpreted as an internal node:
#     leaf(i, data) = SHA256(0x00 || le64(i) || data)   # index-bound
#     node(l, r)    = SHA256(0x01 || l || r)
# Odd node counts promote the lone node unchanged to the next level (no
# duplication -> immune to the CVE-2012-2459 duplicate-leaf ambiguity).
#
# Cross-checked byte-for-byte against merkle_poc.c, which drives the REAL
# in-tree Crypto/Sha2.c. hashlib here is the independent implementation.
import hashlib, sys

def le64(x):
    return x.to_bytes(8, 'little')

def leaf_hash(i, data):
    return hashlib.sha256(b'\x00' + le64(i) + data).digest()

def node_hash(l, r):
    return hashlib.sha256(b'\x01' + l + r).digest()

def build_levels(sectors):
    """Return list of levels bottom->top; level[0] = leaves, last = [root]."""
    level = [leaf_hash(i, s) for i, s in enumerate(sectors)]
    levels = [level]
    while len(level) > 1:
        nxt = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                nxt.append(node_hash(level[i], level[i + 1]))
                i += 2
            else:
                nxt.append(level[i])   # promote lone node
                i += 1
        level = nxt
        levels.append(level)
    return levels

def root(sectors):
    return build_levels(sectors)[-1][0]

def auth_path(sectors, index):
    """Sibling hashes leaf->root for `index`, each tagged with a direction bit
    (0 = sibling is on the right, 1 = sibling is on the left)."""
    levels = build_levels(sectors)
    path = []
    idx = index
    for lvl in levels[:-1]:
        if idx % 2 == 0:
            if idx + 1 < len(lvl):
                path.append((0, lvl[idx + 1]))   # sibling right
            # else lone node promoted: no sibling at this level
        else:
            path.append((1, lvl[idx - 1]))       # sibling left
        idx //= 2
    return path

def verify_path(index, data, path, trusted_root):
    h = leaf_hash(index, data)
    for direction, sib in path:
        h = node_hash(h, sib) if direction == 0 else node_hash(sib, h)
    return h == trusted_root

# ---- deterministic scenario shared with merkle_poc.c ----
N = 8
SECTOR = 64
def make_sectors():
    return [bytes((i * 37 + j * 11 + 3) & 0xff for j in range(SECTOR)) for i in range(N)]

if __name__ == "__main__":
    sectors = make_sectors()
    r = root(sectors)
    print("REF root " + r.hex())
    # authentication path for every leaf (root recomputed from proof == trusted root)
    for i in range(N):
        p = auth_path(sectors, i)
        ok = verify_path(i, sectors[i], p, r)
        # emit the concatenated path so C and Python must agree on the exact siblings
        blob = b''.join(bytes([d]) + s for d, s in p)
        print("REF path_%d %s" % (i, blob.hex()))
        if not ok:
            sys.stderr.write("path %d failed to verify\n" % i)
    # tamper: flip one bit in sector 5 -> root must change, and its path must fail vs old root
    t = list(sectors)
    t[5] = bytes([t[5][0] ^ 0x01]) + t[5][1:]
    r2 = root(t)
    print("REF tamper_root " + r2.hex())
    print("REF tamper_detected " + ("YES" if r2 != r else "NO"))
    print("REF tamper_path_rejected " + ("YES" if not verify_path(5, t[5], auth_path(sectors, 5), r) else "NO"))
