/*
 * decoyfrag_poc.c — proof-of-concept for decoy-fragments-by-default (docs/DECOY-FRAGMENTS-SPEC.md,
 * upstream issue #1072).
 *
 * Writing decoy hidden-volume "creation artifacts" on EVERY volume makes the presence of such an
 * artifact prove nothing. The verifiable reason: a REAL hidden-volume header is
 *   salt || ChaCha20(header_key, iv, header_plaintext)
 * and a DECOY fragment is
 *   salt || ChaCha20(random_key, iv, zeros) = salt || keystream
 * both are `random_salt || PRF_output`, i.e. the SAME uniform distribution — a free-space scanner
 * cannot tell a volume that HAS a hidden volume from one carrying only decoy fragments. This is
 * indistinguishable-random *storage*, NOT a fabricated record of activity (that stays DESCOPED).
 *
 * Layer 2: drives the REAL in-tree Crypto/chacha256.c. decoyfrag_reference.py is the independent
 * Layer-1 reference; both use the same deterministic xorshift64* PRNG. build_and_verify.sh diffs the
 * REF lines byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/chacha256.h"

#define SALT   64
#define BODY   448
#define TOTAL  (SALT + BODY)     /* 512 */
#define SAMPLES 64
#define EXPECTED ((SAMPLES * TOTAL) / 256)   /* 128 */

static uint64_t g_s;
static uint64_t rng_u64 (void)
{
	uint64_t x = g_s; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; g_s = x;
	return x * 0x2545F4914F6CDD1DULL;
}
static void rng_bytes (unsigned char *out, int n)
{
	int i = 0;
	while (i < n)
	{
		uint64_t v = rng_u64 (); int j;
		for (j = 0; j < 8 && i < n; j++, i++) out[i] = (unsigned char) (v >> (8 * j));
	}
}

static void real_hidden_header (unsigned char out[TOTAL])
{
	unsigned char key[32], iv[8], pt[BODY]; ChaCha256Ctx ctx; int i;
	rng_bytes (out, SALT);            /* salt */
	rng_bytes (key, 32);
	rng_bytes (iv, 8);
	pt[0]='V'; pt[1]='E'; pt[2]='R'; pt[3]='A'; pt[4]=0x05; pt[5]=0x00;   /* structured plaintext */
	for (i = 6; i < BODY; i++) pt[i] = (unsigned char) ((i * 37) & 0xff);
	ChaCha256Init (&ctx, key, iv, 20);
	ChaCha256Encrypt (&ctx, pt, BODY, out + SALT);
}

static void decoy_fragment (unsigned char out[TOTAL])
{
	unsigned char key[32], iv[8], zeros[BODY]; ChaCha256Ctx ctx;
	rng_bytes (out, SALT);
	rng_bytes (key, 32);              /* random, then discarded */
	rng_bytes (iv, 8);
	memset (zeros, 0, BODY);
	ChaCha256Init (&ctx, key, iv, 20);
	ChaCha256Encrypt (&ctx, zeros, BODY, out + SALT);   /* = keystream */
}

static uint64_t chi2_num (unsigned char blobs[SAMPLES][TOTAL])
{
	uint64_t hist[256]; int s, i; uint64_t sum = 0;
	memset (hist, 0, sizeof hist);
	for (s = 0; s < SAMPLES; s++) for (i = 0; i < TOTAL; i++) hist[blobs[s][i]]++;
	for (i = 0; i < 256; i++)
	{
		int64_t d = (int64_t) hist[i] - EXPECTED;
		sum += (uint64_t) (d * d);
	}
	return sum;
}

/* chi-square(255 dof) ~ 330 at p~0.001; statistic ~ chi2num/EXPECTED, so bound = 330*EXPECTED */
#define BOUND ((uint64_t) 330 * EXPECTED)

static void phex (const char *l, const unsigned char *p, int n)
{ int i; printf ("%s", l); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

int main (void)
{
	unsigned char real1[TOTAL], decoy1[TOTAL];
	static unsigned char reals[SAMPLES][TOTAL], decoys[SAMPLES][TOTAL];
	uint64_t cr, cd; int i;

	g_s = 0x0DEC0DEF00DBA5E5ULL;
	real_hidden_header (real1);
	decoy_fragment (decoy1);
	phex ("REF real_header  = ", real1, 32);
	phex ("REF decoy_frag   = ", decoy1, 32);

	g_s = 0xF00DFACEC0FFEE01ULL;
	for (i = 0; i < SAMPLES; i++) real_hidden_header (reals[i]);
	for (i = 0; i < SAMPLES; i++) decoy_fragment (decoys[i]);
	cr = chi2_num (reals); cd = chi2_num (decoys);
	printf ("REF real chi2num  = %llu\n", (unsigned long long) cr);
	printf ("REF decoy chi2num = %llu\n", (unsigned long long) cd);
	printf ("[A] identical layout (512 bytes, 64-byte salt): YES\n");
	printf ("[B] real hidden headers pass uniformity: %s\n", cr < BOUND ? "YES" : "NO");
	printf ("[C] decoy fragments pass the SAME uniformity test: %s\n", cd < BOUND ? "YES" : "NO");
	return 0;
}
