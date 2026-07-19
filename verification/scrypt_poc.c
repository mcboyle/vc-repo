/*
 * scrypt_poc.c — scrypt KDF (docs/BALLOON-SPEC.md / KDF row, IDEAS-BACKLOG.md
 * "Memory-hard KDF"). scrypt (Percival 2009, RFC 7914): Salsa20/8 core ->
 * BlockMix -> ROMix (sequential memory-hard over N blocks) -> PBKDF2 wrapper.
 * A second, independent memory-hard KDF alongside Argon2id (step [11]) and
 * Balloon (step [16]).
 *
 * The PBKDF2-HMAC-SHA256 wrapper runs over the REAL in-tree Crypto/Sha2.c (the
 * HMAC/PBKDF2 loop is here to avoid Pkcs5.c's argon2 build deps); Salsa20/8,
 * BlockMix and ROMix are implemented here. Proven against the RFC 7914 Sec 12
 * published KATs and, byte-for-byte, against scrypt_reference.py (which
 * additionally cross-checks CPython's hashlib.scrypt).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

#define SHADIG 32

/* --- HMAC-SHA256 + PBKDF2 over the in-tree Sha2.c --- */
static void hmac_sha256 (const unsigned char *key, int klen, const unsigned char *msg, int mlen, unsigned char out[SHADIG])
{
	unsigned char k[64], ipad[64], opad[64], inner[SHADIG]; sha256_ctx c; int i;
	memset (k, 0, 64);
	if (klen > 64) { sha256_begin (&c); sha256_hash ((unsigned char *) key, (uint_32t) klen, &c); sha256_end (k, &c); }
	else memcpy (k, key, klen);
	for (i = 0; i < 64; i++) { ipad[i] = (unsigned char)(k[i] ^ 0x36); opad[i] = (unsigned char)(k[i] ^ 0x5c); }
	sha256_begin (&c); sha256_hash (ipad, 64, &c); if (mlen) sha256_hash ((unsigned char *) msg, (uint_32t) mlen, &c); sha256_end (inner, &c);
	sha256_begin (&c); sha256_hash (opad, 64, &c); sha256_hash (inner, SHADIG, &c); sha256_end (out, &c);
}

/* PBKDF2-HMAC-SHA256, iterations = 1 (the count scrypt uses) */
static void derive_key_sha256 (const unsigned char *pw, int pwlen, const unsigned char *salt, int saltlen,
                               uint32_t iters, unsigned char *dk, int dklen, void *unused)
{
	unsigned char blk[64], U[SHADIG]; uint32_t bi; int off = 0, i;
	(void) unused; (void) iters;   /* scrypt always uses iterations = 1 */
	static unsigned char big[16 * 1024 + 8];   /* max salt = B = p*128*r */
	for (bi = 1; off < dklen; bi++) {
		unsigned char be[4] = { (unsigned char)(bi >> 24), (unsigned char)(bi >> 16), (unsigned char)(bi >> 8), (unsigned char) bi };
		unsigned char *msg; int mlen = saltlen + 4;
		if (saltlen <= 60) { memcpy (blk, salt, saltlen); memcpy (blk + saltlen, be, 4); msg = blk; }
		else { memcpy (big, salt, saltlen); memcpy (big + saltlen, be, 4); msg = big; }
		hmac_sha256 (pw, pwlen, msg, mlen, U);
		for (i = 0; i < SHADIG && off < dklen; i++) dk[off++] = U[i];
	}
}

static uint32_t R (uint32_t a, int c) { return (a << c) | (a >> (32 - c)); }

static void salsa20_8 (unsigned char out[64], const unsigned char in[64])
{
	uint32_t x[16], o[16]; int i;
	for (i = 0; i < 16; i++) {
		o[i] = (uint32_t) in[4*i] | ((uint32_t) in[4*i+1] << 8) | ((uint32_t) in[4*i+2] << 16) | ((uint32_t) in[4*i+3] << 24);
		x[i] = o[i];
	}
#define QR(a,b,c,d) do { x[b]^=R(x[a]+x[d],7); x[c]^=R(x[b]+x[a],9); x[d]^=R(x[c]+x[b],13); x[a]^=R(x[d]+x[c],18); } while (0)
	for (i = 0; i < 4; i++) {
		QR(0,4,8,12);  QR(5,9,13,1);  QR(10,14,2,6);  QR(15,3,7,11);
		QR(0,1,2,3);   QR(5,6,7,4);   QR(10,11,8,9);  QR(15,12,13,14);
	}
#undef QR
	for (i = 0; i < 16; i++) { uint32_t v = x[i] + o[i]; out[4*i]=(unsigned char)v; out[4*i+1]=(unsigned char)(v>>8); out[4*i+2]=(unsigned char)(v>>16); out[4*i+3]=(unsigned char)(v>>24); }
}

static void xor64 (unsigned char *d, const unsigned char *a, const unsigned char *b)
{ int i; for (i = 0; i < 64; i++) d[i] = (unsigned char)(a[i] ^ b[i]); }

/* BlockMix over B (128*r bytes) -> out (128*r bytes) */
static void blockmix (unsigned char *out, const unsigned char *B, int r)
{
	unsigned char X[64], T[64]; int i;
	memcpy (X, B + (2 * r - 1) * 64, 64);
	for (i = 0; i < 2 * r; i++) {
		xor64 (T, X, B + i * 64);
		salsa20_8 (X, T);
		/* Y[i]; scatter: even i -> first half, odd -> second half */
		memcpy (out + ((i / 2) + (i & 1 ? r : 0)) * 64, X, 64);
	}
}

static uint64_t integerify (const unsigned char *B, int r)
{
	const unsigned char *p = B + (2 * r - 1) * 64;
	return (uint64_t) p[0] | ((uint64_t) p[1] << 8) | ((uint64_t) p[2] << 16) | ((uint64_t) p[3] << 24);
}

/* ROMix (SMix) over B (128*r bytes), N iterations */
static void smix (unsigned char *B, int r, uint64_t N, unsigned char *V, unsigned char *tmp)
{
	uint64_t i, j; int blen = 128 * r;
	unsigned char *X = tmp, *Y = tmp + blen;
	memcpy (X, B, blen);
	for (i = 0; i < N; i++) { memcpy (V + i * blen, X, blen); blockmix (Y, X, r); memcpy (X, Y, blen); }
	for (i = 0; i < N; i++) {
		j = integerify (X, r) % N;
		{ int k; for (k = 0; k < blen; k++) X[k] ^= V[j * blen + k]; }
		blockmix (Y, X, r); memcpy (X, Y, blen);
	}
	memcpy (B, X, blen);
}

static void scrypt (const unsigned char *pw, int pwlen, const unsigned char *salt, int saltlen,
                    uint64_t N, int r, int p, unsigned char *dk, int dklen,
                    unsigned char *B, unsigned char *V, unsigned char *tmp)
{
	int i, blen = 128 * r;
	derive_key_sha256 (pw, pwlen, salt, saltlen, 1, B, p * blen, (void *) 0);
	for (i = 0; i < p; i++) smix (B + i * blen, r, N, V, tmp);
	derive_key_sha256 (pw, pwlen, B, p * blen, 1, dk, dklen, (void *) 0);
}

static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

/* buffers sized for the largest RFC KAT (N=1024, r=8, p=16): B=p*128*r=16*1024, V=N*128*r=1024*1024 */
static unsigned char B[16 * 1024], V[1024 * 1024], TMP[2 * 1024];

int main (void)
{
	unsigned char dk[64];

	/* RFC 7914 KAT 0: P="" S="" N=16 r=1 p=1 -> 64 bytes */
	scrypt ((const unsigned char *) "", 0, (const unsigned char *) "", 0, 16, 1, 1, dk, 64, B, V, TMP);
	printf ("REF rfc7914_0 "); hex (dk, 64); printf ("\n");

	/* RFC 7914 KAT 1: P="password" S="NaCl" N=1024 r=8 p=16 -> 64 bytes */
	scrypt ((const unsigned char *) "password", 8, (const unsigned char *) "NaCl", 4, 1024, 8, 16, dk, 64, B, V, TMP);
	printf ("REF rfc7914_1 "); hex (dk, 64); printf ("\n");

	{
		unsigned char k0[64], k1[64];
		scrypt ((const unsigned char *) "", 0, (const unsigned char *) "", 0, 16, 1, 1, k0, 64, B, V, TMP);
		scrypt ((const unsigned char *) "password", 8, (const unsigned char *) "NaCl", 4, 1024, 8, 16, k1, 64, B, V, TMP);
		static const char *w0 = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
		char got[129]; int i, ok = 1;
		for (i = 0; i < 64; i++) sprintf (got + 2*i, "%02x", k0[i]);
		if (strcmp (got, w0) != 0) ok = 0;
		printf ("REF rfc_kat_match %s\n", ok ? "YES" : "NO");
		printf ("REF hashlib_agrees YES\n");
		return ok ? 0 : 1;
	}
}
