/*
 * adiantum_poc.c — Adiantum (XChaCha12 / AES-256 / NH+Poly1305) wide-block mode
 * driven through the REAL in-tree VeraCrypt crypto objects. Adiantum encrypts a
 * whole sector as ONE block: flipping any ciphertext bit scrambles the entire
 * sector on decrypt. That kills the 16-byte-granular malleability XTS leaves
 * open (an attacker can corrupt one chosen 16-byte block of an XTS sector
 * without touching its neighbours; under Adiantum the same flip destroys all
 * 4096 bytes) — the natural bulk-mode companion to the per-sector MAC work.
 *
 *   ks = XChaCha12(K, nonce 01||0^23, 1136B);  KE=ks[0:32] rt=ks[32:48]
 *                                              rm=ks[48:64] KN=ks[64:1136]
 *   H(T,L) = Poly1305_rt(le128(8|L|) || T) + Poly1305_rm(NH_KN(pad16(L)))
 *   PM = PR + H(T,PL);  CM = AES256_KE(PM);
 *   CL = PL xor XChaCha12(K, CM||01||0^7);  CR = CM - H(T,CL)   (mod 2^128)
 *
 * Real objects exercised: Crypto/chacha256.c supplies EVERY ChaCha keystream
 * byte (key schedule second stage and bulk stream: ChaCha256Init(...,12) over
 * zeros), Crypto/Aescrypt.c+Aeskey.c+Aestab.c the AES-256 block (FIPS-197
 * anchor printed below), and the step-[18] poly1305.h the epsilon-Delta hash
 * (r||0^16 key => exactly poly_hrbar mod 2^128; its RFC partial-block padding
 * equals the reference's c = LE(chunk) + 2^(8*len) term). Implemented locally,
 * honestly: HChaCha12 — chacha256.c does not export the keyless permutation
 * (no feedforward, words 0-3/12-15 out), so it is transcribed here; a bug in
 * it cannot hide because every official KAT depends on it. Also local: NH,
 * the 128-bit LE add/sub combine, the HBSH wrapper, hex parsing.
 *
 * Proven two ways: all 18 official google/adiantum vectors (adiantum_kats.h,
 * every message/tweak length combination) encrypt AND decrypt byte-for-byte,
 * and adiantum_reference.py reproduces the same REF lines independently —
 * build_and_verify.sh diffs them. Limits: a PoC of the mode's math only — no
 * volume-format integration, no claim about side channels, and Adiantum is
 * malleability-hardening, not authentication (a MAC still detects, Adiantum
 * only amplifies, tampering).
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "Crypto/chacha256.h"
#include "Crypto/Aes.h"
#include "poly1305.h"
#include "adiantum_kats.h"

#define MAX_MSG   4096
#define MAX_TWEAK 64

/* ---- little-endian helpers ---- */
static uint32_t ld32 (const unsigned char *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void st32 (unsigned char *p, uint32_t v)
{ p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24); }
static void st64 (unsigned char *p, uint64_t v)
{ st32 (p, (uint32_t)v); st32 (p + 4, (uint32_t)(v >> 32)); }

/* ---- HChaCha12 (local; see header comment) ---- */
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a,b,c,d) \
	a += b; d = ROTL32 (d ^ a, 16); c += d; b = ROTL32 (b ^ c, 12); \
	a += b; d = ROTL32 (d ^ a,  8); c += d; b = ROTL32 (b ^ c,  7);

static void hchacha12 (const unsigned char key[32], const unsigned char in16[16], unsigned char out[32])
{
	uint32_t x[16];
	int i;
	x[0] = 0x61707865; x[1] = 0x3320646E; x[2] = 0x79622D32; x[3] = 0x6B206574;
	for (i = 0; i < 8; i++) x[4 + i]  = ld32 (key + 4 * i);
	for (i = 0; i < 4; i++) x[12 + i] = ld32 (in16 + 4 * i);
	for (i = 0; i < 6; i++)		/* 12 rounds = 6 double rounds; no feedforward */
	{
		QR (x[0], x[4], x[8],  x[12]);
		QR (x[1], x[5], x[9],  x[13]);
		QR (x[2], x[6], x[10], x[14]);
		QR (x[3], x[7], x[11], x[15]);
		QR (x[0], x[5], x[10], x[15]);
		QR (x[1], x[6], x[11], x[12]);
		QR (x[2], x[7], x[8],  x[13]);
		QR (x[3], x[4], x[9],  x[14]);
	}
	for (i = 0; i < 4; i++) st32 (out + 4 * i,      x[i]);
	for (i = 0; i < 4; i++) st32 (out + 16 + 4 * i, x[12 + i]);
}

/* XChaCha12: HChaCha12 subkey (local), then the REAL in-tree ChaCha12 stream.
 * ChaCha256Encrypt XORs in with keystream, so in == the data gives stream-xor
 * directly and in == zeros gives raw keystream. */
static void xchacha12_xor (const unsigned char key[32], const unsigned char nonce24[24],
                           const unsigned char *in, size_t len, unsigned char *out)
{
	unsigned char subkey[32];
	ChaCha256Ctx ctx;
	hchacha12 (key, nonce24, subkey);
	ChaCha256Init (&ctx, subkey, nonce24 + 16, 12);
	ChaCha256Encrypt (&ctx, in, len, out);
}

/* ---- key schedule ---- */
typedef struct
{
	unsigned char k[32];		/* outer key (bulk-stream key) */
	unsigned char rt[16], rm[16];
	unsigned char kn[1072];		/* NH key: 268 LE u32 words */
	aes_encrypt_ctx enc;
	aes_decrypt_ctx dec;
} adiantum_key;

static void adiantum_setkey (const unsigned char key[32], adiantum_key *ak)
{
	unsigned char nonce[24], zeros[1136], ks[1136];
	memset (nonce, 0, sizeof nonce); nonce[0] = 0x01;
	memset (zeros, 0, sizeof zeros);
	xchacha12_xor (key, nonce, zeros, sizeof ks, ks);
	memcpy (ak->k, key, 32);
	memcpy (ak->rt, ks + 32, 16);
	memcpy (ak->rm, ks + 48, 16);
	memcpy (ak->kn, ks + 64, 1072);
	aes_encrypt_key256 (ks, &ak->enc);	/* KE = ks[0:32] */
	aes_decrypt_key256 (ks, &ak->dec);
}

/* ---- NH (local): chunk len multiple of 16, at most 1024 bytes ---- */
static void nh_hash (const unsigned char *kn, const unsigned char *chunk, size_t len, unsigned char out[32])
{
	uint32_t m[256], kw[268];
	size_t nw = len / 4, i;
	int p;
	for (i = 0; i < nw;  i++) m[i]  = ld32 (chunk + 4 * i);
	for (i = 0; i < 268; i++) kw[i] = ld32 (kn + 4 * i);
	for (p = 0; p < 4; p++)
	{
		size_t off = 4 * (size_t)p;	/* key offset in 32-bit WORDS */
		uint64_t sum = 0;
		for (i = 0; i < nw; i += 4)
		{
			sum += (uint64_t)(uint32_t)(m[i]     + kw[off + i])     * (uint32_t)(m[i + 2] + kw[off + i + 2]);
			sum += (uint64_t)(uint32_t)(m[i + 1] + kw[off + i + 1]) * (uint32_t)(m[i + 3] + kw[off + i + 3]);
		}
		st64 (out + 8 * p, sum);
	}
}

/* ---- 128-bit LE arithmetic mod 2^128 ---- */
static void add128 (unsigned char a[16], const unsigned char b[16])
{
	unsigned int carry = 0; int i;
	for (i = 0; i < 16; i++) { carry += (unsigned int)a[i] + b[i]; a[i] = (unsigned char)carry; carry >>= 8; }
}
static void sub128 (unsigned char a[16], const unsigned char b[16])
{
	int borrow = 0, i;
	for (i = 0; i < 16; i++)
	{
		int d = (int)a[i] - (int)b[i] - borrow;
		borrow = d < 0; a[i] = (unsigned char)(d & 0xff);
	}
}

/* poly_hrbar via the step-[18] Poly1305: key = r || 0^16, so the final +s adds
 * nothing and the tag is exactly the hash mod 2^128, 16 LE bytes. */
static void poly_hrbar (const unsigned char r16[16], const unsigned char *msg, size_t len, unsigned char out[16])
{
	unsigned char key32[32];
	memcpy (key32, r16, 16); memset (key32 + 16, 0, 16);
	poly1305 (out, msg, len, key32);
}

/* H(T, L): bit length of the UNPADDED L, then L zero-padded to 16 for NH. */
static void adiantum_hash (const adiantum_key *ak, const unsigned char *tweak, size_t tlen,
                           const unsigned char *l, size_t llen, unsigned char out[16])
{
	unsigned char msg1[16 + MAX_TWEAK];
	unsigned char padded[MAX_MSG], nhcat[4 * 32], h2[16];
	size_t plen = (llen + 15) & ~(size_t)15, off, cat = 0;

	memset (msg1, 0, 16);
	st64 (msg1, (uint64_t)llen * 8);	/* le128(8*|L|): high 8 bytes stay 0 */
	memcpy (msg1 + 16, tweak, tlen);
	poly_hrbar (ak->rt, msg1, 16 + tlen, out);

	if (llen > 0)
	{
		memcpy (padded, l, llen);
		memset (padded + llen, 0, plen - llen);
		for (off = 0; off < plen; off += 1024, cat += 32)
			nh_hash (ak->kn, padded + off, (plen - off) < 1024 ? (plen - off) : 1024, nhcat + cat);
		poly_hrbar (ak->rm, nhcat, cat, h2);
		add128 (out, h2);
	}
}

/* ---- HBSH encrypt/decrypt (message >= 16 bytes) ---- */
static void adiantum_encrypt (const adiantum_key *ak, const unsigned char *tweak, size_t tlen,
                              const unsigned char *pt, size_t len, unsigned char *ct)
{
	unsigned char pm[16], cm[16], h[16], nonce[24];
	size_t llen = len - 16;

	adiantum_hash (ak, tweak, tlen, pt, llen, h);
	memcpy (pm, pt + llen, 16);
	add128 (pm, h);				/* PM = PR + H(T, PL) */
	aes_encrypt (pm, cm, &ak->enc);		/* CM = AES256-E(KE, PM) */

	memcpy (nonce, cm, 16); nonce[16] = 0x01; memset (nonce + 17, 0, 7);
	xchacha12_xor (ak->k, nonce, pt, llen, ct);	/* CL = PL xor stream */

	adiantum_hash (ak, tweak, tlen, ct, llen, h);
	memcpy (ct + llen, cm, 16);
	sub128 (ct + llen, h);			/* CR = CM - H(T, CL) */
}

static void adiantum_decrypt (const adiantum_key *ak, const unsigned char *tweak, size_t tlen,
                              const unsigned char *ct, size_t len, unsigned char *pt)
{
	unsigned char cm[16], pm[16], h[16], nonce[24];
	size_t llen = len - 16;

	adiantum_hash (ak, tweak, tlen, ct, llen, h);
	memcpy (cm, ct + llen, 16);
	add128 (cm, h);				/* CM = CR + H(T, CL) */

	memcpy (nonce, cm, 16); nonce[16] = 0x01; memset (nonce + 17, 0, 7);
	xchacha12_xor (ak->k, nonce, ct, llen, pt);	/* PL = CL xor stream */

	aes_decrypt (cm, pm, &ak->dec);		/* PM = AES256-D(KE, CM) */
	adiantum_hash (ak, tweak, tlen, pt, llen, h);
	memcpy (pt + llen, pm, 16);
	sub128 (pt + llen, h);			/* PR = PM - H(T, PL) */
}

/* ---- harness ---- */
static size_t hexparse (const char *s, unsigned char *out)
{
	size_t n = 0;
	while (s[0] && s[1])
	{
		unsigned int b; char t[3] = { s[0], s[1], 0 };
		sscanf (t, "%2x", &b);
		out[n++] = (unsigned char)b; s += 2;
	}
	return n;
}
static void hexprint (const unsigned char *b, size_t n)
{ size_t i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

static size_t hamming (const unsigned char *a, const unsigned char *b, size_t n)
{
	size_t i, bits = 0;
	for (i = 0; i < n; i++) { unsigned char d = a[i] ^ b[i]; while (d) { bits += d & 1; d >>= 1; } }
	return bits;
}

int main (void)
{
	static unsigned char key[32], tweak[MAX_TWEAK], pt[MAX_MSG], expect[MAX_MSG],
	                     ct[MAX_MSG], back[MAX_MSG], mut[MAX_MSG];
	size_t tlen, mlen;
	int i, ok = 1, all_match = 1, roundtrip = 1;
	adiantum_key ak;

	aes_init ();

	/* AES-256 sanity anchor: FIPS-197 appendix C.3 through the real objects */
	{
		unsigned char k[32], p[16], c[16];
		aes_encrypt_ctx e;
		for (i = 0; i < 32; i++) k[i] = (unsigned char)i;
		hexparse ("00112233445566778899aabbccddeeff", p);
		aes_encrypt_key256 (k, &e);
		aes_encrypt (p, c, &e);
		printf ("REF aes256_fips197 "); hexprint (c, 16); printf ("\n");
	}

	for (i = 0; i < ADIANTUM_NKATS; i++)
	{
		hexparse (adiantum_kats[i][0], key);
		tlen = hexparse (adiantum_kats[i][1], tweak);
		mlen = hexparse (adiantum_kats[i][2], pt);
		hexparse (adiantum_kats[i][3], expect);

		adiantum_setkey (key, &ak);
		adiantum_encrypt (&ak, tweak, tlen, pt, mlen, ct);
		printf ("REF kat_%d ", i); hexprint (ct, mlen); printf ("\n");
		if (memcmp (ct, expect, mlen) != 0) all_match = 0;

		adiantum_decrypt (&ak, tweak, tlen, expect, mlen, back);
		if (memcmp (back, pt, mlen) != 0) roundtrip = 0;
	}
	printf ("REF kat_all_match %s\n", all_match ? "YES" : "NO");
	ok &= all_match;
	printf ("REF roundtrip_all %s\n", roundtrip ? "YES" : "NO");
	ok &= roundtrip;

	/* diffusion / wrong-key / wrong-tweak on the DIFFUSION_IDX vector */
	hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][0], key);
	tlen = hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][1], tweak);
	mlen = hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][2], pt);
	hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][3], expect);
	adiantum_setkey (key, &ak);

	{	/* flip one plaintext bit -> whole ciphertext scrambles */
		int yes;
		memcpy (mut, pt, mlen); mut[0] ^= 0x01;
		adiantum_encrypt (&ak, tweak, tlen, mut, mlen, ct);
		yes = hamming (ct, expect, mlen) * 10 >= 4 * 8 * mlen
			&& memcmp (ct, expect, 16) != 0
			&& memcmp (ct + mlen - 16, expect + mlen - 16, 16) != 0;
		printf ("REF enc_diffusion %s\n", yes ? "YES" : "NO");
		ok &= yes;
	}
	{	/* flip one ciphertext bit -> whole plaintext scrambles */
		int yes;
		memcpy (mut, expect, mlen); mut[0] ^= 0x01;
		adiantum_decrypt (&ak, tweak, tlen, mut, mlen, back);
		yes = hamming (back, pt, mlen) * 10 >= 4 * 8 * mlen
			&& memcmp (back + mlen - 16, pt + mlen - 16, 16) != 0;
		printf ("REF dec_diffusion %s\n", yes ? "YES" : "NO");
		ok &= yes;
	}
	{	/* wrong key */
		adiantum_key wk;
		unsigned char k2[32];
		int yes;
		memcpy (k2, key, 32); k2[0] ^= 0x01;
		adiantum_setkey (k2, &wk);
		adiantum_encrypt (&wk, tweak, tlen, pt, mlen, ct);
		yes = memcmp (ct, expect, mlen) != 0;
		printf ("REF wrongkey %s\n", yes ? "YES" : "NO");
		ok &= yes;
	}
	{	/* wrong tweak */
		unsigned char t2[MAX_TWEAK];
		int yes;
		memcpy (t2, tweak, tlen); t2[0] ^= 0x01;
		adiantum_encrypt (&ak, t2, tlen, pt, mlen, ct);
		yes = memcmp (ct, expect, mlen) != 0;
		printf ("REF wrongtweak %s\n", yes ? "YES" : "NO");
		ok &= yes;
	}

	return ok ? 0 : 1;
}
