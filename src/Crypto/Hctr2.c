/*
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

/*
 * HCTR2 — transcribed from the proven PoC (verification/hctr2_poc.c, suite step [26], all official
 * HCTR2 KATs) with two deliberate changes for shippable form, both noted at their sites:
 *   1. the block cipher is the constant-time src/Crypto/AesCt, not the table-driven in-tree AES
 *      (see the header comment for why, and what it costs);
 *   2. the hash scratch buffer is bounded by HCTR2_MAX_* and the entry points range-check rather than
 *      assuming caller sanity, so a bad length fails closed instead of smashing the stack.
 * The arithmetic is otherwise byte-for-byte the PoC's, so the KATs carry over unchanged.
 */

#include "Crypto/Hctr2.h"

#if defined(VC_ENABLE_HCTR2)

#include <string.h>

#if defined(_MSC_VER)
typedef unsigned __int64 hctr2_u64;
#else
#include <stdint.h>
typedef uint64_t hctr2_u64;
#endif

/* ---- GF(2^128) POLYVAL (RFC 8452): little-endian bit order,
 *      P = x^128 + x^127 + x^126 + x^121 + 1; dot(a,b) = a*b*x^-128 mod P. ---------------------------
 *
 * BRANCH-FREE ON PURPOSE. Both operands are secret here — the POLYVAL key h = E_K(0^128) and the
 * message-derived accumulator s — so a data-dependent `if` over their bits is a timing and
 * branch-prediction side channel that leaks h. This mirrors the arithmetic-mask, fixed-iteration,
 * table-free pattern src/Common/Shamir.c uses for GF(2^8), scaled to 128 bits: every
 * secret-conditioned XOR becomes `(value & mask)` with mask all-ones or all-zeros. The `s ? ... : 0`
 * guards are on s = i & 63, a PUBLIC loop index, not on secret data. Screened at step [74]'s dudect
 * sibling (verification/hctr2_dudect_test.c). Do not reintroduce a branch here.
 */
typedef struct { hctr2_u64 w[4]; } hctr2_u256;

static void gf_dot (const hctr2_u64 a[2], const hctr2_u64 b[2], hctr2_u64 out[2])
{
	hctr2_u256 c; int i, limb;
	memset (&c, 0, sizeof c);
	for (i = 0; i < 128; i++) {
		hctr2_u64 m = (hctr2_u64) 0 - ((a[i >> 6] >> (i & 63)) & (hctr2_u64) 1);
		int w = i >> 6, s = i & 63;
		c.w[w]     ^= (b[0] << s) & m;
		c.w[w + 1] ^= (((s ? (b[0] >> (64 - s)) : 0) ^ (b[1] << s)) & m);
		c.w[w + 2] ^= ((s ? (b[1] >> (64 - s)) : 0) & m);
	}
	/* multiply by x^-128: 128 exact halvings; P has bits 0,121,126,127,128 */
	for (i = 0; i < 128; i++) {
		hctr2_u64 r = (hctr2_u64) 0 - (c.w[0] & (hctr2_u64) 1);
		c.w[0] ^= (hctr2_u64) 1 & r;                                                        /* bit 0       */
		c.w[1] ^= ((((hctr2_u64) 1 << 57) | ((hctr2_u64) 1 << 62) | ((hctr2_u64) 1 << 63)) & r); /* 121,126,127 */
		c.w[2] ^= (hctr2_u64) 1 & r;                                                        /* bit 128     */
		for (limb = 0; limb < 3; limb++)
			c.w[limb] = (c.w[limb] >> 1) | (c.w[limb + 1] << 63);
		c.w[3] >>= 1;
	}
	out[0] = c.w[0]; out[1] = c.w[1];
}

static void ld128 (const unsigned char *p, hctr2_u64 w[2])
{
	int i; w[0] = w[1] = 0;
	for (i = 0; i < 8; i++) w[0] |= (hctr2_u64) p[i]     << (8 * i);
	for (i = 0; i < 8; i++) w[1] |= (hctr2_u64) p[8 + i] << (8 * i);
}

static void st128 (const hctr2_u64 w[2], unsigned char *p)
{
	int i;
	for (i = 0; i < 8; i++) {
		p[i]     = (unsigned char) (w[0] >> (8 * i));
		p[8 + i] = (unsigned char) (w[1] >> (8 * i));
	}
}

static void polyval_buf (const unsigned char hbar[16], const unsigned char *m, size_t len,
                         unsigned char out[16])
{
	hctr2_u64 h[2], s[2], x[2], t[2];
	size_t i;
	s[0] = s[1] = 0;
	ld128 (hbar, h);
	for (i = 0; i < len; i += 16) {
		ld128 (m + i, x);
		s[0] ^= x[0]; s[1] ^= x[1];
		gf_dot (s, h, t);
		s[0] = t[0]; s[1] = t[1];
	}
	st128 (s, out);
}

/* ---- HCTR2 proper ------------------------------------------------------------------------------- */

void Hctr2Init (Hctr2Key *hk, const unsigned char key[32])
{
	unsigned char z[16];
	AesCtInit256 (&hk->blk, key);
	memset (z, 0, sizeof z);              AesCtEncryptBlock (&hk->blk, z, hk->hbar);
	memset (z, 0, sizeof z); z[0] = 0x01; AesCtEncryptBlock (&hk->blk, z, hk->L);
	{ volatile unsigned char *p = z; size_t n = sizeof z; while (n--) *p++ = 0; }
}

/* H(T, M): length block || zero-padded tweak || (M | pad(M||0x01)) */
static void hctr2_hash (const Hctr2Key *hk, const unsigned char *tweak, size_t tlen,
                        const unsigned char *msg, size_t mlen, unsigned char out[16])
{
	unsigned char buf[16 + HCTR2_MAX_TWEAK + HCTR2_MAX_SECTOR + 16];
	size_t w, i;
	int rem = (mlen % 16) != 0;
	hctr2_u64 lb = (hctr2_u64) tlen * 8 * 2 + 2 + (rem ? 1 : 0);

	memset (buf, 0, sizeof buf);
	for (i = 0; i < 8; i++) buf[i] = (unsigned char) (lb >> (8 * i));
	w = 16;
	if (tlen > 0) memcpy (buf + w, tweak, tlen);
	w += tlen + ((16 - tlen % 16) % 16);
	if (mlen > 0) memcpy (buf + w, msg, mlen);
	if (rem) { buf[w + mlen] = 0x01; w += mlen + 1 + ((16 - (mlen + 1) % 16) % 16); }
	else       w += mlen;

	polyval_buf (hk->hbar, buf, w, out);
	{ volatile unsigned char *p = buf; size_t n = sizeof buf; while (n--) *p++ = 0; }
}

/* XCTR keystream XORed into dst: block i (counting from 1) = E_K(S ^ le64(i) padded) */
static void hctr2_xctr_xor (const Hctr2Key *hk, const unsigned char S[16],
                            const unsigned char *src, unsigned char *dst, size_t len)
{
	unsigned char blk[16], ks[16];
	size_t off = 0, n, j;
	hctr2_u64 i = 1;
	while (off < len) {
		memcpy (blk, S, 16);
		for (j = 0; j < 8; j++) blk[j] ^= (unsigned char) (i >> (8 * j));
		AesCtEncryptBlock (&hk->blk, blk, ks);
		n = (len - off < 16) ? (len - off) : 16;
		for (j = 0; j < n; j++) dst[off + j] = (unsigned char) (src[off + j] ^ ks[j]);
		off += n; i++;
	}
	{ volatile unsigned char *p = ks; size_t z = sizeof ks; while (z--) *p++ = 0; }
}

static int hctr2_crypt (const Hctr2Key *hk, int enc, const unsigned char *tweak, size_t tlen,
                        const unsigned char *in, size_t len, unsigned char *out)
{
	unsigned char first[16], ff[16], dig[16], S[16];
	size_t blen;
	int j;

	/* Fail closed rather than trusting the caller: the scratch buffer in hctr2_hash is sized by these
	   bounds, and a wide-block mode has no meaningful behaviour below one block. */
	if (len < HCTR2_MIN_LEN || len > HCTR2_MAX_SECTOR || tlen > HCTR2_MAX_TWEAK)
		return 0;

	blen = len - 16;

	/* MM = M ^ H(T,N)   (dec: UU = U ^ H(T,V)) */
	hctr2_hash (hk, tweak, tlen, in + 16, blen, dig);
	for (j = 0; j < 16; j++) first[j] = (unsigned char) (in[j] ^ dig[j]);

	/* UU = E(MM)   (dec: MM = D(UU)) */
	if (enc) AesCtEncryptBlock (&hk->blk, first, ff);
	else     AesCtDecryptBlock (&hk->blk, first, ff);

	/* S = MM ^ UU ^ L */
	for (j = 0; j < 16; j++) S[j] = (unsigned char) (first[j] ^ ff[j] ^ hk->L[j]);

	/* V = N ^ XCTR(S)   (dec: N = V ^ XCTR(S)).  in == out is fine: the first block is read into
	   `first`/`ff` before this point, and XCTR is a byte-wise XOR at matching offsets. */
	hctr2_xctr_xor (hk, S, in + 16, out + 16, blen);

	/* U = UU ^ H(T,V)   (dec: M = MM ^ H(T,N)) */
	hctr2_hash (hk, tweak, tlen, out + 16, blen, dig);
	for (j = 0; j < 16; j++) out[j] = (unsigned char) (ff[j] ^ dig[j]);

	{ volatile unsigned char *p = first; size_t z = sizeof first; while (z--) *p++ = 0; }
	{ volatile unsigned char *p = ff;    size_t z = sizeof ff;    while (z--) *p++ = 0; }
	{ volatile unsigned char *p = dig;   size_t z = sizeof dig;   while (z--) *p++ = 0; }
	{ volatile unsigned char *p = S;     size_t z = sizeof S;     while (z--) *p++ = 0; }
	return 1;
}

int Hctr2Encrypt (const Hctr2Key *hk, const unsigned char *tweak, size_t tlen,
                  const unsigned char *pt, size_t len, unsigned char *ct)
{
	return hctr2_crypt (hk, 1, tweak, tlen, pt, len, ct);
}

int Hctr2Decrypt (const Hctr2Key *hk, const unsigned char *tweak, size_t tlen,
                  const unsigned char *ct, size_t len, unsigned char *pt)
{
	return hctr2_crypt (hk, 0, tweak, tlen, ct, len, pt);
}

#endif /* VC_ENABLE_HCTR2 */
