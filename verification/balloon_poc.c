/*
 * balloon_poc.c — proof-of-concept for the Balloon memory-hard KDF (docs/BALLOON-SPEC.md,
 * IDEAS-BACKLOG.md §C). A candidate to sit alongside Argon2id in the KDF seam: provably memory-hard,
 * built on VeraCrypt's in-tree SHA-256, with explicit space (blocks) and time (rounds) costs.
 *
 * See balloon_reference.py for the algorithm. This drives the REAL in-tree Crypto/Sha2.c; the Python
 * reference is independent (hashlib). build_and_verify.sh diffs the REF lines byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

#define DIGEST   32
#define DELTA    3
#define MAX_N    64

static unsigned char g_buf[MAX_N][DIGEST];

static void le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

/* one SHA-256 over up to 5 (ptr,len) parts */
static void H (unsigned char out[DIGEST],
               const unsigned char *p0, int n0, const unsigned char *p1, int n1,
               const unsigned char *p2, int n2, const unsigned char *p3, int n3,
               const unsigned char *p4, int n4)
{
	sha256_ctx c; sha256_begin (&c);
	if (n0) sha256_hash (p0, (uint_32t) n0, &c);
	if (n1) sha256_hash (p1, (uint_32t) n1, &c);
	if (n2) sha256_hash (p2, (uint_32t) n2, &c);
	if (n3) sha256_hash (p3, (uint_32t) n3, &c);
	if (n4) sha256_hash (p4, (uint_32t) n4, &c);
	sha256_end (out, &c);
}

static void balloon (const unsigned char *pw, int pwLen, const unsigned char *salt, int saltLen,
                     int s_cost, int t_cost, unsigned char out[DIGEST])
{
	int n = s_cost, m, t, i;
	uint64_t cnt = 0;
	unsigned char cb[8], tb[8], mb[8], ib[8];

	/* Expand */
	le64 (cnt++, cb);
	H (g_buf[0], cb, 8, pw, pwLen, salt, saltLen, 0, 0, 0, 0);
	for (m = 1; m < n; m++) { le64 (cnt++, cb); H (g_buf[m], cb, 8, g_buf[m-1], DIGEST, 0,0,0,0,0,0); }

	/* Mix */
	for (t = 0; t < t_cost; t++)
	{
		for (m = 0; m < n; m++)
		{
			unsigned char *prev = g_buf[(m + n - 1) % n];
			le64 (cnt++, cb);
			H (g_buf[m], cb, 8, prev, DIGEST, g_buf[m], DIGEST, 0,0,0,0);   /* absorbs old buf[m] */
			for (i = 0; i < DELTA; i++)
			{
				unsigned char idx[DIGEST]; uint64_t other; int b;
				le64 (cnt++, cb); le64 ((uint64_t) t, tb); le64 ((uint64_t) m, mb); le64 ((uint64_t) i, ib);
				H (idx, cb, 8, tb, 8, mb, 8, ib, 8, salt, saltLen);
				other = 0; for (b = 0; b < 8; b++) other |= ((uint64_t) idx[b]) << (8 * b);
				other %= (uint64_t) n;
				le64 (cnt++, cb);
				H (g_buf[m], cb, 8, g_buf[m], DIGEST, g_buf[(int) other], DIGEST, 0,0,0,0);
			}
		}
	}
	memcpy (out, g_buf[n-1], DIGEST);
}

static void phex (const char *l, const unsigned char *p, int n)
{ int i; printf ("%s", l); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

int main (void)
{
	const char *PW = "correct horse battery staple";
	unsigned char salt[16], z16[16], out[DIGEST], out2[DIGEST];
	int i, pwl = (int) strlen (PW);
	for (i = 0; i < 16; i++) salt[i] = (unsigned char) ((i * 5 + 1) & 0xff);
	memset (z16, 0, 16);

	balloon ((const unsigned char *) PW, pwl, salt, 16, 16, 3, out);
	phex ("REF balloon(s=16,t=3) = ", out, DIGEST);

	balloon ((const unsigned char *) PW, pwl, salt, 16, 16, 3, out2);
	printf ("REF deterministic (same inputs -> same output) = %s\n", memcmp (out, out2, DIGEST) == 0 ? "YES" : "NO");
	balloon ((const unsigned char *) PW, pwl, z16, 16, 16, 3, out2);
	printf ("REF different salt -> different output = %s\n", memcmp (out, out2, DIGEST) != 0 ? "YES" : "NO");
	balloon ((const unsigned char *) PW, pwl, salt, 16, 32, 3, out2);
	printf ("REF different space cost -> different output = %s\n", memcmp (out, out2, DIGEST) != 0 ? "YES" : "NO");
	balloon ((const unsigned char *) PW, pwl, salt, 16, 16, 5, out2);
	printf ("REF different time cost -> different output = %s\n", memcmp (out, out2, DIGEST) != 0 ? "YES" : "NO");
	return 0;
}
