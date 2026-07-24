/*
 * Adiantum wide-block mode (XChaCha12 / AES-256 / NH+Poly1305). Shippable form of the proven PoC
 * verification/adiantum_poc.c (steps [24] and [89]). See Adiantum.h for scope/gating/dependencies.
 *
 *   ks = XChaCha12(K, nonce 01||0^23, 1136B);  KE=ks[0:32] rt=ks[32:48] rm=ks[48:64] KN=ks[64:1136]
 *   H(T,L) = Poly1305_rt(le128(8|L|) || T) + Poly1305_rm(NH_KN(pad16(L)))     (mod 2^128)
 *   PM = PR + H(T,PL);  CM = AES256_KE(PM);
 *   CL = PL xor XChaCha12(K, CM||01||0^7);  CR = CM - H(T,CL)                 (mod 2^128)
 *
 * The math is transcribed byte-for-byte from the PoC that reproduces every official google/adiantum KAT;
 * only the block cipher (AesCt), stream (chacha256) and polynomial hash (Poly1305) are the real in-tree
 * objects rather than PoC-local copies. HChaCha12 (the keyless permutation chacha256.c does not export),
 * NH and the 128-bit LE add/sub are Adiantum-specific and kept local, exactly as in the proven PoC.
 */

#include "Crypto/Adiantum.h"

#if defined(VC_ENABLE_ADIANTUM)

#include <string.h>
#include <stdint.h>
#include "Crypto/chacha256.h"
#include "Crypto/Poly1305.h"

/* ---- little-endian helpers ---- */
static uint32_t ld32 (const unsigned char *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void st32 (unsigned char *p, uint32_t v)
{ p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24); }
static void st64 (unsigned char *p, uint64_t v)
{ st32 (p, (uint32_t)v); st32 (p + 4, (uint32_t)(v >> 32)); }

/* ---- HChaCha12 (local: chacha256.c does not export the keyless permutation) ---- */
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

/* XChaCha12: HChaCha12 subkey (local), then the REAL in-tree ChaCha12 stream. ChaCha256Encrypt XORs in
 * with keystream, so in==data gives stream-xor and in==zeros gives raw keystream. */
static void xchacha12_xor (const unsigned char key[32], const unsigned char nonce24[24],
                           const unsigned char *in, size_t len, unsigned char *out)
{
	unsigned char subkey[32];
	ChaCha256Ctx ctx;
	hchacha12 (key, nonce24, subkey);
	ChaCha256Init (&ctx, subkey, nonce24 + 16, 12);
	ChaCha256Encrypt (&ctx, in, len, out);
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

/* poly_hrbar via Poly1305: key = r || 0^16, so the final +s adds nothing and the tag is exactly the hash
 * mod 2^128 (16 LE bytes). */
static void poly_hrbar (const unsigned char r16[16], const unsigned char *msg, size_t len, unsigned char out[16])
{
	unsigned char key32[32];
	memcpy (key32, r16, 16); memset (key32 + 16, 0, 16);
	Poly1305 (out, msg, len, key32);
}

/* H(T, L): bit length of the UNPADDED L, then L zero-padded to 16 for NH. */
static void adiantum_hash (const AdiantumKey *ak, const unsigned char *tweak, size_t tlen,
                           const unsigned char *l, size_t llen, unsigned char out[16])
{
	unsigned char msg1[16 + ADIANTUM_MAX_TWEAK];
	unsigned char padded[ADIANTUM_MAX_SECTOR], nhcat[4 * 32], h2[16];
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

/* ---- key schedule ---- */
void AdiantumInit (AdiantumKey *ak, const unsigned char key[32])
{
	unsigned char nonce[24], zeros[1136], ks[1136];
	memset (nonce, 0, sizeof nonce); nonce[0] = 0x01;
	memset (zeros, 0, sizeof zeros);
	xchacha12_xor (key, nonce, zeros, sizeof ks, ks);
	memcpy (ak->k, key, 32);
	memcpy (ak->rt, ks + 32, 16);
	memcpy (ak->rm, ks + 48, 16);
	memcpy (ak->kn, ks + 64, 1072);
	AesCtInit256 (&ak->blk, ks);		/* KE = ks[0:32]; one expanded key for enc + dec */
}

/* ---- HBSH encrypt/decrypt (len in [16, ADIANTUM_MAX_SECTOR]) ---- */
int AdiantumEncrypt (const AdiantumKey *ak, const unsigned char *tweak, size_t tlen,
                     const unsigned char *pt, size_t len, unsigned char *ct)
{
	unsigned char pm[16], cm[16], h[16], nonce[24];
	size_t llen;
	if (len < 16 || len > ADIANTUM_MAX_SECTOR || tlen > ADIANTUM_MAX_TWEAK) return 0;
	llen = len - 16;

	adiantum_hash (ak, tweak, tlen, pt, llen, h);
	memcpy (pm, pt + llen, 16);
	add128 (pm, h);				/* PM = PR + H(T, PL) */
	AesCtEncryptBlock (&ak->blk, pm, cm);	/* CM = AES256-E(KE, PM), constant-time */

	memcpy (nonce, cm, 16); nonce[16] = 0x01; memset (nonce + 17, 0, 7);
	xchacha12_xor (ak->k, nonce, pt, llen, ct);	/* CL = PL xor stream */

	adiantum_hash (ak, tweak, tlen, ct, llen, h);
	memcpy (ct + llen, cm, 16);
	sub128 (ct + llen, h);			/* CR = CM - H(T, CL) */
	return 1;
}

int AdiantumDecrypt (const AdiantumKey *ak, const unsigned char *tweak, size_t tlen,
                     const unsigned char *ct, size_t len, unsigned char *pt)
{
	unsigned char cm[16], pm[16], h[16], nonce[24];
	size_t llen;
	if (len < 16 || len > ADIANTUM_MAX_SECTOR || tlen > ADIANTUM_MAX_TWEAK) return 0;
	llen = len - 16;

	adiantum_hash (ak, tweak, tlen, ct, llen, h);
	memcpy (cm, ct + llen, 16);
	add128 (cm, h);				/* CM = CR + H(T, CL) */

	memcpy (nonce, cm, 16); nonce[16] = 0x01; memset (nonce + 17, 0, 7);
	xchacha12_xor (ak->k, nonce, ct, llen, pt);	/* PL = CL xor stream */

	AesCtDecryptBlock (&ak->blk, cm, pm);	/* PM = AES256-D(KE, CM), constant-time */
	adiantum_hash (ak, tweak, tlen, pt, llen, h);
	memcpy (pt + llen, pm, 16);
	sub128 (pt + llen, h);			/* PR = PM - H(T, PL) */
	return 1;
}

#endif /* VC_ENABLE_ADIANTUM */
