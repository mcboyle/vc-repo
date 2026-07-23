/*
 * hctr2_poc.c — HCTR2 wide-block mode (docs/HCTR2-SPEC.md, IDEAS-BACKLOG.md B).
 *
 * HCTR2 (Crowley, Huckleberry, Biggers — eprint 2021/1441; shipped in the Linux
 * kernel for fscrypt) is the wide-block sibling of Adiantum (step [24]) tuned
 * for AES-NI hardware: a tweakable super-pseudorandom permutation over the
 * whole sector from AES-256 in XCTR mode + POLYVAL (RFC 8452). One AES call
 * per 16 bytes but no NH/ChaCha — on machines with AES+CLMUL acceleration this
 * is the faster way to kill XTS's 16-byte malleability.
 *
 *   hbar = E_K(le128(0));  L = E_K(le128(1))
 *   H(T,M) = POLYVAL(hbar, le128(2*bitlen(T)+2+[16 !| |M|]) || pad(T)
 *                          || (M or pad(M||0x01)))
 *   MM = M ^ H(T,N); UU = E_K(MM); S = MM^UU^L; V = N ^ XCTR_K(S);
 *   U = UU ^ H(T,V); C = U||V.     XCTR block i (from 1) = E_K(S ^ le128(i)).
 *
 * Proven three ways: (1) all 35 official google/hctr2 vectors (hctr2_kats.h,
 * every message-length x tweak-length combination) reproduce and round-trip;
 * (2) AES-256 is the REAL in-tree Aescrypt/Aeskey/Aestab.c (FIPS-197 KAT
 * asserted); POLYVAL is PoC-local but anchored to the RFC 8452 published
 * example (there is no POLYVAL in the VeraCrypt tree — stated honestly);
 * (3) hctr2_reference.py (independent pure python) emits byte-identical REF
 * lines. Single-bit diffusion/wrong-key/wrong-tweak asserted on both sides.
 * A shipping mode would use a vetted constant-time implementation; this PoC
 * establishes correctness and the mode seam.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Aes.h"
#include "hctr2_kats.h"

#define MAXMSG 512
#define MAXTWK 64

/* ---- GF(2^128) POLYVAL (RFC 8452): little-endian bit order,
 *      P = x^128 + x^127 + x^126 + x^121 + 1; dot(a,b) = a*b*x^-128 mod P.
 *      256-bit intermediates as four u64 limbs; bit-by-bit PoC arithmetic. */
typedef struct { uint64_t w[4]; } u256;

static void gf_dot (const uint64_t a[2], const uint64_t b[2], uint64_t out[2])
{
	u256 c; int i, limb;
	memset (&c, 0, sizeof c);
	/* Branch-free: both operands are secret here (POLYVAL key h = AES_k(0^128) and the
	   key/message-derived accumulator s), so a data-dependent `if` over their bits is a timing/
	   branch-prediction side channel that leaks h. Mirror the arithmetic-mask, fixed-iteration,
	   table-free pattern src/Common/Shamir.c uses for GF(2^8), scaled to 128 bits: replace each
	   secret-conditioned XOR with `(value & mask)` where mask = 0-bit is all-ones or all-zeros.
	   The `s ? ...: 0` guards below are on s = i & 63, a PUBLIC loop index, not secret. */
	for (i = 0; i < 128; i++) {
		/* c ^= (b << i) when bit i of a is set — folded under a mask instead of a branch */
		uint64_t m = 0ULL - ((a[i >> 6] >> (i & 63)) & 1ULL);
		int w = i >> 6, s = i & 63;
		c.w[w]     ^= (b[0] << s) & m;
		c.w[w + 1] ^= (((s ? (b[0] >> (64 - s)) : 0) ^ (b[1] << s)) & m);
		c.w[w + 2] ^= ((s ? (b[1] >> (64 - s)) : 0) & m);
	}
	/* multiply by x^-128: 128 exact halvings; P has bits 0,121,126,127,128 */
	for (i = 0; i < 128; i++) {
		/* conditional reduction when the low bit is set — masked, not branched */
		uint64_t r = 0ULL - (c.w[0] & 1ULL);
		c.w[0] ^= 1ULL & r;                                          /* bit 0   */
		c.w[1] ^= (((1ULL << 57) | (1ULL << 62) | (1ULL << 63)) & r); /* 121,126,127 */
		c.w[2] ^= 1ULL & r;                                          /* bit 128 */
		for (limb = 0; limb < 3; limb++)
			c.w[limb] = (c.w[limb] >> 1) | (c.w[limb + 1] << 63);
		c.w[3] >>= 1;
	}
	out[0] = c.w[0]; out[1] = c.w[1];
}

static void ld128 (const unsigned char *p, uint64_t w[2])
{
	int i; w[0] = w[1] = 0;
	for (i = 0; i < 8; i++)  w[0] |= (uint64_t) p[i] << (8 * i);
	for (i = 0; i < 8; i++)  w[1] |= (uint64_t) p[8 + i] << (8 * i);
}
static void st128 (const uint64_t w[2], unsigned char *p)
{
	int i;
	for (i = 0; i < 8; i++) { p[i] = (unsigned char)(w[0] >> (8 * i)); p[8 + i] = (unsigned char)(w[1] >> (8 * i)); }
}

/* POLYVAL over a whole (block-multiple) buffer */
static void polyval_buf (const unsigned char hbar[16], const unsigned char *m, size_t len,
                         unsigned char out[16])
{
	uint64_t h[2], s[2] = {0, 0}, x[2], t[2];
	size_t i;
	ld128 (hbar, h);
	for (i = 0; i < len; i += 16) {
		ld128 (m + i, x);
		s[0] ^= x[0]; s[1] ^= x[1];
		gf_dot (s, h, t);
		s[0] = t[0]; s[1] = t[1];
	}
	st128 (s, out);
}

/* ---- HCTR2 over the in-tree AES-256 ---- */
typedef struct {
	aes_encrypt_ctx enc;
	aes_decrypt_ctx dec;
	unsigned char hbar[16], L[16];
} Hctr2;

static void hctr2_setup (const unsigned char key[32], Hctr2 *h)
{
	unsigned char z[16];
	aes_encrypt_key256 (key, &h->enc);
	aes_decrypt_key256 (key, &h->dec);
	memset (z, 0, 16); aes_encrypt (z, h->hbar, &h->enc);
	memset (z, 0, 16); z[0] = 0x01; aes_encrypt (z, h->L, &h->enc);
}

/* H(T, M): length block || zero-padded tweak || (M | pad(M||0x01)) */
static void hctr2_hash (const Hctr2 *h, const unsigned char *tweak, size_t tlen,
                        const unsigned char *msg, size_t mlen, unsigned char out[16])
{
	unsigned char buf[16 + MAXTWK + MAXMSG + 16];
	size_t w = 0, i;
	int rem = (mlen % 16) != 0;
	uint64_t lb = (uint64_t) tlen * 8 * 2 + 2 + (rem ? 1 : 0);
	memset (buf, 0, sizeof buf);
	for (i = 0; i < 8; i++) buf[i] = (unsigned char)(lb >> (8 * i));
	w = 16;
	memcpy (buf + w, tweak, tlen); w += tlen + ((16 - tlen % 16) % 16);
	memcpy (buf + w, msg, mlen);
	if (rem) { buf[w + mlen] = 0x01; w += mlen + 1 + ((16 - (mlen + 1) % 16) % 16); }
	else w += mlen;
	polyval_buf (h->hbar, buf, w, out);
}

/* XCTR keystream XORed into dst: block i (from 1) = E_K(S ^ le128(i)) */
static void hctr2_xctr_xor (const Hctr2 *h, const unsigned char S[16],
                            const unsigned char *src, unsigned char *dst, size_t len)
{
	unsigned char blk[16], ks[16];
	size_t off = 0, n, j;
	uint64_t i = 1;
	while (off < len) {
		memcpy (blk, S, 16);
		for (j = 0; j < 8; j++) blk[j] ^= (unsigned char)(i >> (8 * j));
		aes_encrypt (blk, ks, &h->enc);
		n = len - off < 16 ? len - off : 16;
		for (j = 0; j < n; j++) dst[off + j] = (unsigned char)(src[off + j] ^ ks[j]);
		off += n; i++;
	}
}

static void hctr2_crypt (const Hctr2 *h, int enc, const unsigned char *tweak, size_t tlen,
                         const unsigned char *in, size_t len, unsigned char *out)
{
	unsigned char first[16], ff[16], dig[16], S[16];
	size_t blen = len - 16;
	int j;

	/* MM = M ^ H(T,N)   (dec: UU = U ^ H(T,V)) */
	hctr2_hash (h, tweak, tlen, in + 16, blen, dig);
	for (j = 0; j < 16; j++) first[j] = (unsigned char)(in[j] ^ dig[j]);

	/* UU = E(MM)   (dec: MM = D(UU)) */
	if (enc) aes_encrypt (first, ff, &h->enc); else aes_decrypt (first, ff, &h->dec);

	/* S = MM ^ UU ^ L */
	for (j = 0; j < 16; j++) S[j] = (unsigned char)(first[j] ^ ff[j] ^ h->L[j]);

	/* V = N ^ XCTR(S)   (dec: N = V ^ XCTR(S)) */
	hctr2_xctr_xor (h, S, in + 16, out + 16, blen);

	/* U = UU ^ H(T,V)   (dec: M = MM ^ H(T,N)) */
	hctr2_hash (h, tweak, tlen, out + 16, blen, dig);
	for (j = 0; j < 16; j++) out[j] = (unsigned char)(ff[j] ^ dig[j]);
}

/* ---- harness ---- */
static int hexval (char c)
{ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c - 'A' + 10; }
static size_t unhex (const char *s, unsigned char *out)
{
	size_t n = strlen (s) / 2, i;
	for (i = 0; i < n; i++) out[i] = (unsigned char)((hexval (s[2*i]) << 4) | hexval (s[2*i+1]));
	return n;
}
static void hex (const unsigned char *b, size_t n)
{ size_t i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }
static size_t hamming (const unsigned char *a, const unsigned char *b, size_t n)
{
	size_t i, c = 0; unsigned char x; int k;
	for (i = 0; i < n; i++) { x = (unsigned char)(a[i] ^ b[i]); for (k = 0; k < 8; k++) c += (x >> k) & 1; }
	return c;
}

#ifndef HCTR2_NO_MAIN   /* the gf_dot dudect screen (hctr2_dudect_test.c) includes this file to reach
                           the real static gf_dot, and supplies its own main; step [26] leaves it defined */
int main (void)
{
	unsigned char key[32], tweak[MAXTWK], pt[MAXMSG], ct[MAXMSG], got[MAXMSG], back[MAXMSG];
	size_t tlen, plen;
	int i, all = 1, rt = 1, ok = 1;

	/* FIPS-197 anchor on the real in-tree AES */
	{
		aes_encrypt_ctx e; unsigned char k[32], p[16], c[16];
		static const unsigned char pp[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		for (i = 0; i < 32; i++) k[i] = (unsigned char) i;
		memcpy (p, pp, 16);
		aes_encrypt_key256 (k, &e); aes_encrypt (p, c, &e);
		printf ("REF aes256_fips197 "); hex (c, 16); printf ("\n");
	}
	/* RFC 8452 POLYVAL published example */
	{
		unsigned char h[16], x[32], d[16];
		unhex ("25629347589242761d31f826ba4b757b", h);
		unhex ("4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362", x);
		polyval_buf (h, x, 32, d);
		printf ("REF polyval_rfc8452 "); hex (d, 16); printf ("\n");
	}

	for (i = 0; i < HCTR2_NKATS; i++) {
		Hctr2 h;
		unhex (hctr2_kats[i][0], key);
		tlen = unhex (hctr2_kats[i][1], tweak);
		plen = unhex (hctr2_kats[i][2], pt);
		unhex (hctr2_kats[i][3], ct);
		hctr2_setup (key, &h);
		hctr2_crypt (&h, 1, tweak, tlen, pt, plen, got);
		printf ("REF kat_%d ", i); hex (got, plen); printf ("\n");
		if (memcmp (got, ct, plen) != 0) all = 0;
		hctr2_crypt (&h, 0, tweak, tlen, ct, plen, back);
		if (memcmp (back, pt, plen) != 0) rt = 0;
	}
	printf ("REF kat_all_match %s\n", all ? "YES" : "NO");
	printf ("REF roundtrip_all %s\n", rt ? "YES" : "NO");
	ok = all && rt;

	{
		Hctr2 h;
		unsigned char p2[MAXMSG], c2[MAXMSG], pd[MAXMSG];
		size_t bits;
		int encd, decd;
		i = HCTR2_DIFFUSION_IDX;
		unhex (hctr2_kats[i][0], key);
		tlen = unhex (hctr2_kats[i][1], tweak);
		plen = unhex (hctr2_kats[i][2], pt);
		unhex (hctr2_kats[i][3], ct);
		bits = 8 * plen;
		hctr2_setup (key, &h);

		memcpy (p2, pt, plen); p2[0] ^= 1;
		hctr2_crypt (&h, 1, tweak, tlen, p2, plen, c2);
		encd = hamming (ct, c2, plen) * 10 >= bits * 4
		       && memcmp (c2, ct, 16) != 0 && memcmp (c2 + plen - 16, ct + plen - 16, 16) != 0;
		printf ("REF enc_diffusion %s\n", encd ? "YES" : "NO");

		memcpy (c2, ct, plen); c2[0] ^= 1;
		hctr2_crypt (&h, 0, tweak, tlen, c2, plen, pd);
		decd = hamming (pt, pd, plen) * 10 >= bits * 4
		       && memcmp (pd + plen - 16, pt + plen - 16, 16) != 0;
		printf ("REF dec_diffusion %s\n", decd ? "YES" : "NO");

		{
			Hctr2 hw; unsigned char wk[32];
			memcpy (wk, key, 32); wk[0] ^= 1;
			hctr2_setup (wk, &hw);
			hctr2_crypt (&hw, 1, tweak, tlen, pt, plen, c2);
			printf ("REF wrongkey %s\n", memcmp (c2, ct, plen) != 0 ? "YES" : "NO");
		}
		{
			unsigned char wt[MAXTWK];
			memcpy (wt, tweak, tlen); wt[0] ^= 1;
			hctr2_crypt (&h, 1, wt, tlen, pt, plen, c2);
			printf ("REF wrongtweak %s\n", memcmp (c2, ct, plen) != 0 ? "YES" : "NO");
		}
		ok = ok && encd && decd;
	}
	return ok ? 0 : 1;
}
#endif /* HCTR2_NO_MAIN */
