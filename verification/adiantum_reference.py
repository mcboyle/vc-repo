#!/usr/bin/env python3
"""Independent reference for Adiantum_XChaCha12_32_AES256 (the length-preserving
wide-block mode from Crowley & Biggers, "Adiantum: length-preserving encryption
for entry-level processors", IACR ToSC 2018-4), written from the spec so the
in-tree C side (adiantum_poc.c) has something to disagree with. Structure and
test vectors follow google/adiantum (MIT, github.com/google/adiantum); the code
here is a from-scratch transcription of the algorithm, not a copy.

Adiantum is HBSH: hash - block cipher - stream - hash, over a 16-byte block:
    PM = PR + H(T, PL)            (mod 2^128, blocks read little-endian)
    CM = AES-256-Encrypt(K_E, PM)
    CL = PL xor XChaCha12(K, CM || 01 || 0^7)
    CR = CM - H(T, CL)            (mod 2^128)
with H = Poly1305(rt, bitlen(L) || T) + Poly1305(rm, NH(K_N, pad(L))) and all
subkeys drawn from one XChaCha12 keystream under nonce 01 || 0^23. Everything
(ChaCha, HChaCha12, NH, Poly1305, and a single-block AES-256 with tables
generated at runtime) is implemented below from the standard-library only.

Proof is two-way: (1) the 18 official Google KATs — every ciphertext matched
byte-for-byte and round-tripped through Decrypt — plus a FIPS-197 AES anchor;
(2) build_and_verify.sh diffs these REF lines against the compiled C
implementation. Limits stated honestly: this is variable-time big-int Python
for verification only, never a production cipher; and passing KATs proves the
math, not the safety of any particular disk-encryption deployment of it.
"""
import sys
import adiantum_kats

MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = (1 << 128) - 1
P1305 = (1 << 130) - 5


# ---------------------------------------------------------------- ChaCha core

def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def _quarterround(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK32; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32; s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha_rounds(s, nrounds):
    for _ in range(nrounds // 2):
        _quarterround(s, 0, 4, 8, 12)
        _quarterround(s, 1, 5, 9, 13)
        _quarterround(s, 2, 6, 10, 14)
        _quarterround(s, 3, 7, 11, 15)
        _quarterround(s, 0, 5, 10, 15)
        _quarterround(s, 1, 6, 11, 12)
        _quarterround(s, 2, 7, 8, 13)
        _quarterround(s, 3, 4, 9, 14)


def _le32_words(b):
    return [int.from_bytes(b[i:i + 4], 'little') for i in range(0, len(b), 4)]


_CHACHA_CONST = _le32_words(b"expand 32-byte k")


def chacha12_block(key, counter, nonce8):
    """One 64-byte ChaCha12 block (DJB layout: 64-bit LE counter, 8-byte nonce)."""
    init = (_CHACHA_CONST + _le32_words(key)
            + [counter & MASK32, (counter >> 32) & MASK32] + _le32_words(nonce8))
    s = list(init)
    _chacha_rounds(s, 12)
    return b''.join(((s[i] + init[i]) & MASK32).to_bytes(4, 'little')
                    for i in range(16))


def hchacha12(key, in16):
    """HChaCha12: no feedforward; output words [0..3, 12..15] serialized LE."""
    s = _CHACHA_CONST + _le32_words(key) + _le32_words(in16)
    _chacha_rounds(s, 12)
    return b''.join(s[i].to_bytes(4, 'little') for i in (0, 1, 2, 3, 12, 13, 14, 15))


def xchacha12_stream(key, nonce24, nbytes):
    """XChaCha12 keystream: subkey = HChaCha12(key, nonce[0:16]), iv = nonce[16:24]."""
    subkey = hchacha12(key, nonce24[:16])
    iv = nonce24[16:24]
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out += chacha12_block(subkey, counter, iv)
        counter += 1
    return bytes(out[:nbytes])


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------- AES-256 (single block)
# Tables generated at runtime from GF(2^8) with the FIPS-197 polynomial 0x11b:
# S-box = affine(x^-1), inverse S-box by inversion of the table.

def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
    return r


def _ginv(a):
    # a^254 = a^-1 in GF(2^8) (0 maps to 0 per FIPS-197)
    r, x, e = 1, a, 254
    while e:
        if e & 1:
            r = _gmul(r, x)
        x = _gmul(x, x)
        e >>= 1
    return r


def _make_sboxes():
    sbox = [0] * 256
    for a in range(256):
        v = _ginv(a) if a else 0
        s = 0x63
        for i in range(5):
            s ^= ((v << i) | (v >> (8 - i))) & 0xff
        sbox[a] = s
    inv = [0] * 256
    for a, s in enumerate(sbox):
        inv[s] = a
    return sbox, inv


_SBOX, _INV_SBOX = _make_sboxes()


def _aes256_key_schedule(key):
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(words[i - 1])
        if i % 8 == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif i % 8 == 4:
            t = [_SBOX[x] for x in t]
        words.append([a ^ b for a, b in zip(words[i - 8], t)])
    return [bytes(sum(words[4 * r:4 * r + 4], [])) for r in range(15)]


def _shift_rows(s):
    return bytes(s[(i + 4 * (i % 4)) % 16] for i in range(16))


def _inv_shift_rows(s):
    return bytes(s[(i - 4 * (i % 4)) % 16] for i in range(16))


def _mix_columns(s, inverse=False):
    coef = (14, 11, 13, 9) if inverse else (2, 3, 1, 1)
    out = bytearray(16)
    for c in range(0, 16, 4):
        col = s[c:c + 4]
        for r in range(4):
            out[c + r] = (_gmul(coef[(0 - r) % 4], col[0])
                          ^ _gmul(coef[(1 - r) % 4], col[1])
                          ^ _gmul(coef[(2 - r) % 4], col[2])
                          ^ _gmul(coef[(3 - r) % 4], col[3]))
    return bytes(out)


def aes256_encrypt_block(key, block):
    rk = _aes256_key_schedule(key)
    s = _xor(block, rk[0])
    for rnd in range(1, 14):
        s = _mix_columns(_shift_rows(bytes(_SBOX[x] for x in s)))
        s = _xor(s, rk[rnd])
    s = _shift_rows(bytes(_SBOX[x] for x in s))
    return _xor(s, rk[14])


def aes256_decrypt_block(key, block):
    rk = _aes256_key_schedule(key)
    s = _xor(block, rk[14])
    for rnd in range(13, 0, -1):
        s = bytes(_INV_SBOX[x] for x in _inv_shift_rows(s))
        s = _mix_columns(_xor(s, rk[rnd]), inverse=True)
    s = bytes(_INV_SBOX[x] for x in _inv_shift_rows(s))
    return _xor(s, rk[0])


# ------------------------------------------------------- hash: Poly1305 + NH

def poly_hrbar(r16, msg):
    """Poly1305-style evaluation with clamped r; no key-block addition.
    Result lives mod 2^130-5 and is consumed mod 2^128 by the caller."""
    r = int.from_bytes(r16, 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    h = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        c = int.from_bytes(chunk, 'little') + (1 << (8 * len(chunk)))
        h = (h + c) * r % P1305
    return h


def nh(key_words, chunk):
    """NH over one chunk (len multiple of 16, <= 1024). 4 passes, each offset
    by 4 key WORDS; output = 4 u64 sums serialized LE (32 bytes)."""
    m = _le32_words(chunk)
    out = bytearray()
    for p in range(4):
        off = 4 * p
        acc = 0
        for i in range(0, len(m), 4):
            acc += (((m[i] + key_words[off + i]) & MASK32)
                    * ((m[i + 2] + key_words[off + i + 2]) & MASK32))
            acc += (((m[i + 1] + key_words[off + i + 1]) & MASK32)
                    * ((m[i + 3] + key_words[off + i + 3]) & MASK32))
        out += (acc & MASK64).to_bytes(8, 'little')
    return bytes(out)


def adiantum_hash(rt, rm, nh_key_words, tweak, msg):
    """H(T, L) mod 2^128: bit-length prefix uses the UNPADDED L; NH runs over
    L zero-padded to a multiple of 16, in 1024-byte chunks."""
    ht = poly_hrbar(rt, (8 * len(msg)).to_bytes(16, 'little') + tweak)
    padded = msg + b'\0' * (-len(msg) % 16)
    nhcat = b''.join(nh(nh_key_words, padded[i:i + 1024])
                     for i in range(0, len(padded), 1024))
    return (ht + poly_hrbar(rm, nhcat)) & MASK128


# --------------------------------------------------------------- Adiantum

def _subkeys(key):
    ks = xchacha12_stream(key, b'\x01' + b'\x00' * 23, 1136)
    return ks[0:32], ks[32:48], ks[48:64], _le32_words(ks[64:1136])


def _bulk_nonce(cm):
    return cm + b'\x01' + b'\x00' * 7


def adiantum_encrypt(key, tweak, pt):
    ke, rt, rm, knw = _subkeys(key)
    pl, pr = pt[:-16], pt[-16:]
    pm = ((int.from_bytes(pr, 'little') + adiantum_hash(rt, rm, knw, tweak, pl))
          & MASK128).to_bytes(16, 'little')
    cm = aes256_encrypt_block(ke, pm)
    cl = _xor(pl, xchacha12_stream(key, _bulk_nonce(cm), len(pl)))
    cr = ((int.from_bytes(cm, 'little') - adiantum_hash(rt, rm, knw, tweak, cl))
          & MASK128).to_bytes(16, 'little')
    return cl + cr


def adiantum_decrypt(key, tweak, ct):
    ke, rt, rm, knw = _subkeys(key)
    cl, cr = ct[:-16], ct[-16:]
    cm = ((int.from_bytes(cr, 'little') + adiantum_hash(rt, rm, knw, tweak, cl))
          & MASK128).to_bytes(16, 'little')
    pl = _xor(cl, xchacha12_stream(key, _bulk_nonce(cm), len(cl)))
    pm = aes256_decrypt_block(ke, cm)
    pr = ((int.from_bytes(pm, 'little') - adiantum_hash(rt, rm, knw, tweak, pl))
          & MASK128).to_bytes(16, 'little')
    return pl + pr


# ------------------------------------------------------------------- driver

def _hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def main():
    ok = True

    # FIPS-197 C.3 anchor for the from-scratch AES-256
    aes_out = aes256_encrypt_block(bytes(range(32)),
                                   bytes.fromhex("00112233445566778899aabbccddeeff"))
    print("REF aes256_fips197 %s" % aes_out.hex())
    ok &= aes_out.hex() == "8ea2b7ca516745bfeafc49904b496089"

    kats = [(bytes.fromhex(k), bytes.fromhex(t), bytes.fromhex(p), bytes.fromhex(c))
            for (k, t, p, c) in adiantum_kats.KATS]

    all_match = True
    roundtrip = True
    for i, (k, t, p, c) in enumerate(kats):
        got = adiantum_encrypt(k, t, p)
        print("REF kat_%d %s" % (i, got.hex()))
        all_match &= got == c
        roundtrip &= adiantum_decrypt(k, t, c) == p
    print("REF kat_all_match " + ("YES" if all_match else "NO"))
    print("REF roundtrip_all " + ("YES" if roundtrip else "NO"))
    ok &= all_match and roundtrip

    k, t, p, c = kats[adiantum_kats.DIFFUSION_IDX]

    # flip one plaintext bit -> ciphertext scrambles end to end
    p2 = bytes([p[0] ^ 0x01]) + p[1:]
    c2 = adiantum_encrypt(k, t, p2)
    enc_diff = (_hamming(c2, c) >= 0.4 * 8 * len(c)
                and c2[:16] != c[:16] and c2[-16:] != c[-16:])
    print("REF enc_diffusion " + ("YES" if enc_diff else "NO"))
    ok &= enc_diff

    # flip one ciphertext bit -> plaintext scrambles (incl. the block-cipher tail)
    c3 = bytes([c[0] ^ 0x01]) + c[1:]
    p3 = adiantum_decrypt(k, t, c3)
    dec_diff = _hamming(p3, p) >= 0.4 * 8 * len(p) and p3[-16:] != p[-16:]
    print("REF dec_diffusion " + ("YES" if dec_diff else "NO"))
    ok &= dec_diff

    wk = bytes([k[0] ^ 0x01]) + k[1:]
    wrongkey = adiantum_encrypt(wk, t, p) != c
    print("REF wrongkey " + ("YES" if wrongkey else "NO"))
    ok &= wrongkey

    wt = bytes([t[0] ^ 0x01]) + t[1:]
    wrongtweak = adiantum_encrypt(k, wt, p) != c
    print("REF wrongtweak " + ("YES" if wrongtweak else "NO"))
    ok &= wrongtweak

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
