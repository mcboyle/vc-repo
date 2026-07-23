#!/usr/bin/env python3
# Independent BLAKE3 reference (docs/HASHES-SPEC.md, IDEAS-BACKLOG.md table row
# "Hashes"). BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn, 2020) is the
# fast tree/parallel hash: 7-round BLAKE2s-style compression, 1024-byte chunks,
# binary tree with power-of-two left subtrees, built-in keyed and KDF modes and
# arbitrary-length XOF output. Candidate here as a fast keyfile/pool hash and
# tree-hash for the Merkle work. NOT in the VeraCrypt tree, so the proof is the
# official published vectors (blake3_kats.py) + byte-identical agreement with
# blake3_poc.c. Stdlib only.
import sys
import blake3_kats

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL = 16, 32, 64
M32 = 0xFFFFFFFF

def _ror(x, n):
    return ((x >> n) | (x << (32 - n))) & M32

def _g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & M32; v[d] = _ror(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & M32;     v[b] = _ror(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & M32; v[d] = _ror(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & M32;     v[b] = _ror(v[b] ^ v[c], 7)

def _compress(cv, block, counter, blen, flags):
    v = cv[:8] + IV[:4] + [counter & M32, (counter >> 32) & M32, blen, flags]
    m = block[:]
    for r in range(7):
        _g(v, 0, 4, 8, 12, m[0], m[1]);  _g(v, 1, 5, 9, 13, m[2], m[3])
        _g(v, 2, 6, 10, 14, m[4], m[5]); _g(v, 3, 7, 11, 15, m[6], m[7])
        _g(v, 0, 5, 10, 15, m[8], m[9]); _g(v, 1, 6, 11, 12, m[10], m[11])
        _g(v, 2, 7, 8, 13, m[12], m[13]); _g(v, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[PERM[i]] for i in range(16)]
    return [v[i] ^ v[i + 8] for i in range(8)] + [v[i + 8] ^ cv[i] for i in range(8)]

def _words(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

def _blockw(b):
    return _words(b + b'\0' * (64 - len(b)))

class _Output:
    def __init__(self, cv, block, blen, flags):
        self.cv, self.block, self.blen, self.flags = cv, block, blen, flags
    def root_bytes(self, n):
        out = b''
        t = 0
        while len(out) < n:
            w = _compress(self.cv, self.block, t, self.blen, self.flags | ROOT)
            out += b''.join(x.to_bytes(4, 'little') for x in w)
            t += 1
        return out[:n]
    def chain(self, counter):
        return _compress(self.cv, self.block, counter, self.blen, self.flags)[:8]

def _chunk_output(key, chunk, index, base):
    blocks = [chunk[i:i+64] for i in range(0, len(chunk), 64)] or [b'']
    cv = key[:]
    for i, blk in enumerate(blocks):
        flags = base | (CHUNK_START if i == 0 else 0) | (CHUNK_END if i == len(blocks) - 1 else 0)
        if i == len(blocks) - 1:
            return _Output(cv, _blockw(blk), len(blk), flags), index
        cv = _compress(cv, _blockw(blk), index, 64, flags)[:8]

def _subtree_cv(key, chunks, first_index, base):
    if len(chunks) == 1:
        out, idx = _chunk_output(key, chunks[0], first_index, base)
        return out.chain(idx)
    left = 1 << ((len(chunks) - 1).bit_length() - 1)
    l = _subtree_cv(key, chunks[:left], first_index, base)
    r = _subtree_cv(key, chunks[left:], first_index + left, base)
    return _Output(key, l + r, 64, base | PARENT).chain(0)

def blake3(data, key_words=None, base=0, out_len=32):
    key = key_words[:] if key_words else IV[:]
    chunks = [data[i:i+1024] for i in range(0, len(data), 1024)] or [b'']
    if len(chunks) == 1:
        out, _ = _chunk_output(key, chunks[0], 0, base)
        return out.root_bytes(out_len)
    left = 1 << ((len(chunks) - 1).bit_length() - 1)
    l = _subtree_cv(key, chunks[:left], 0, base)
    r = _subtree_cv(key, chunks[left:], left, base)
    return _Output(key, l + r, 64, base | PARENT).root_bytes(out_len)

def blake3_keyed(data, key32, out_len=32):
    return blake3(data, _words(key32), KEYED_HASH, out_len)

def blake3_derive(context, material, out_len=32):
    ck = blake3(context, None, DERIVE_KEY_CONTEXT, 32)
    return blake3(material, _words(ck), DERIVE_KEY_MATERIAL, out_len)

if __name__ == "__main__":
    key = blake3_kats.KEY.encode()
    ctx = blake3_kats.CONTEXT.encode()
    pat = bytes(i % 251 for i in range(102400))
    all_ok = True
    for (n, h, kh, dk) in blake3_kats.CASES:
        m = pat[:n]
        got_h = blake3(m, out_len=131).hex()
        got_k = blake3_keyed(m, key, 131).hex()
        got_d = blake3_derive(ctx, m, 131).hex()
        print("REF hash_%d %s" % (n, got_h))
        print("REF keyed_%d %s" % (n, got_k))
        print("REF derive_%d %s" % (n, got_d))
        all_ok = all_ok and got_h == h and got_k == kh and got_d == dk
    print("REF all_match " + ("YES" if all_ok else "NO"))
    sys.exit(0 if all_ok else 1)
