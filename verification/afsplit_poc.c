/*
 * afsplit_poc.c — proof-of-concept for anti-forensic (AF) splitting (docs/AF-SPLIT-SPEC.md,
 * IDEAS-BACKLOG.md P0.3). The concrete answer to the SSD-remnant caveat.
 *
 * Before a keyslot's wrapped key is written, diffuse it across s stripes (LUKS/TKS1 AFsplit) so that
 * recovering the key needs ALL s stripes; a partial recovery (a wear-leveling remnant) yields nothing.
 * See afsplit_reference.py for the algorithm. This drives the REAL in-tree Crypto/Sha2.c; the Python
 * reference is independent (hashlib). build_and_verify.sh diffs the REF lines byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

#define N   128     /* material length (multiple of 32) */
#define S   4       /* stripes */
#define DS  32      /* SHA-256 digest size */

static uint64_t g_s;
static uint64_t rng_u64 (void)
{ uint64_t x = g_s; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; g_s = x; return x * 0x2545F4914F6CDD1DULL; }
static void rng_bytes (unsigned char *out, int n)
{ int i = 0; while (i < n){ uint64_t v = rng_u64(); int j; for (j=0;j<8&&i<n;j++,i++) out[i]=(unsigned char)(v>>(8*j)); } }

static void xorb (const unsigned char *a, const unsigned char *b, unsigned char *out, int n)
{ int i; for (i=0;i<n;i++) out[i]=(unsigned char)(a[i]^b[i]); }

/* LUKS diffuse: SHA-256 each 32-byte section with its big-endian section index prepended */
static void diffuse (const unsigned char *src, unsigned char *dst, int n)
{
	int i, sec = n / DS;
	for (i = 0; i < sec; i++)
	{
		sha256_ctx c; unsigned char iv[4];
		iv[0]=(unsigned char)(i>>24); iv[1]=(unsigned char)(i>>16); iv[2]=(unsigned char)(i>>8); iv[3]=(unsigned char)i;
		sha256_begin (&c);
		sha256_hash (iv, 4, &c);
		sha256_hash (src + i*DS, DS, &c);
		sha256_end (dst + i*DS, &c);
	}
}

static void af_split (const unsigned char *key, int n, int s, unsigned char stripes[S][N])
{
	unsigned char buf[N], t[N]; int i;
	memset (buf, 0, n);
	for (i = 0; i < s - 1; i++)
	{
		rng_bytes (stripes[i], n);
		xorb (buf, stripes[i], t, n);
		diffuse (t, buf, n);
	}
	xorb (key, buf, stripes[s-1], n);
}

static void af_merge (unsigned char stripes[S][N], int n, int s, unsigned char *out)
{
	unsigned char buf[N], t[N]; int i;
	memset (buf, 0, n);
	for (i = 0; i < s - 1; i++)
	{
		xorb (buf, stripes[i], t, n);
		diffuse (t, buf, n);
	}
	xorb (stripes[s-1], buf, out, n);
}

static void hexdigest (unsigned char stripes[S][N], int n, int s, char out[65])
{
	sha256_ctx c; unsigned char h[32]; int i;
	sha256_begin (&c);
	for (i = 0; i < s; i++) sha256_hash (stripes[i], (uint_32t) n, &c);
	sha256_end (h, &c);
	for (i = 0; i < 32; i++) sprintf (out + 2*i, "%02x", h[i]);
	out[64] = 0;
}

int main (void)
{
	unsigned char key[N], stripes[S][N], merged[N]; int i, j; char dig[65];

	for (i = 0; i < N; i++) key[i] = (unsigned char) ((0x60 + i) & 0xff);
	g_s = 0xA5F00DCAFEBABE01ULL;
	af_split (key, N, S, stripes);
	hexdigest (stripes, N, S, dig);
	printf ("REF split total len = %d\n", S * N);
	printf ("REF split hash = %s\n", dig);

	af_merge (stripes, N, S, merged);
	printf ("REF merge recovers key = %s\n", memcmp (merged, key, N) == 0 ? "YES" : "NO");

	{
		int ok = 1;
		for (j = 0; j < S; j++)
		{
			unsigned char dam[S][N], out[N];
			memcpy (dam, stripes, sizeof dam);
			memset (dam[j], 0, N);
			af_merge (dam, N, S, out);
			if (memcmp (out, key, N) == 0) ok = 0;
		}
		printf ("REF any missing stripe defeats recovery = %s\n", ok ? "YES" : "NO");
	}
	printf ("REF final stripe alone != key = %s\n", memcmp (stripes[S-1], key, N) != 0 ? "YES" : "NO");
	return 0;
}
