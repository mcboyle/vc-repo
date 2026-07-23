/*
 * catena_poc.c — Catena-BRG-style memory-hard KDF core (build_and_verify.sh step [48];
 * IDEAS-BACKLOG "memory-hard alternatives to benchmark against Argon2id"). A survey entry beside
 * Balloon (step [16]) and scrypt (step [34]): the bit-reversal-graph (BRG) memory-hard core in the
 * Catena style (Forler-Lucks-Wenzel), over the REAL in-tree SHA-256 (Crypto/Sha2.c). Sequential fill
 * of 2^g blocks, then lambda BRG passes whose bit-reversal permutation forces whole-array access.
 *
 * This is the memory-hard CORE, not the full Catena KDF (no keyed tweak / client-independent-update
 * wrapper); catena_reference.py is the independent reference and build_and_verify.sh diffs the REF
 * lines byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

#define DIGEST 32
#define MAX_G  12
#define MAX_N  (1 << MAX_G)

static unsigned char g_v[MAX_N][DIGEST];
static unsigned char g_r[MAX_N][DIGEST];

static void le64 (uint64_t x, unsigned char out[8]) { int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

static void H (unsigned char out[DIGEST],
               const unsigned char *p0, int n0, const unsigned char *p1, int n1, const unsigned char *p2, int n2)
{
	sha256_ctx c; sha256_begin (&c);
	if (n0) sha256_hash (p0, (uint_32t) n0, &c);
	if (n1) sha256_hash (p1, (uint_32t) n1, &c);
	if (n2) sha256_hash (p2, (uint_32t) n2, &c);
	sha256_end (out, &c);
}

static uint32_t brg (uint32_t i, int g)
{
	uint32_t r = 0; int k;
	for (k = 0; k < g; k++) { r = (r << 1) | (i & 1u); i >>= 1; }
	return r;
}

static void catena_brg (const unsigned char *pw, int pwLen, const unsigned char *salt, int saltLen,
                        int g, int lam, unsigned char out[DIGEST])
{
	uint32_t n = 1u << g, i; int t;
	unsigned char cb[8];

	le64 (0, cb);
	H (g_v[0], cb, 8, pw, pwLen, salt, saltLen);
	for (i = 1; i < n; i++) { le64 (i, cb); H (g_v[i], cb, 8, g_v[i-1], DIGEST, 0, 0); }

	for (t = 0; t < lam; t++)
	{
		H (g_r[0], g_v[n-1], DIGEST, g_v[brg (0, g)], DIGEST, 0, 0);
		for (i = 1; i < n; i++)
			H (g_r[i], g_r[i-1], DIGEST, g_v[brg (i, g)], DIGEST, 0, 0);
		memcpy (g_v, g_r, (size_t) n * DIGEST);
	}
	memcpy (out, g_v[n-1], DIGEST);
}

static void phex (const char *l, const unsigned char *p, int n) { int i; printf ("%s", l); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

int main (void)
{
	const char *PW = "correct horse battery staple";
	unsigned char salt[16], out[DIGEST], out2[DIGEST]; int i, pwl = (int) strlen (PW);
	for (i = 0; i < 16; i++) salt[i] = (unsigned char) ((i * 5 + 1) & 0xff);

	catena_brg ((const unsigned char*) PW, pwl, salt, 16, 8, 3, out);
	phex ("REF catena(g=8,lam=3) = ", out, DIGEST);
	catena_brg ((const unsigned char*) PW, pwl, salt, 16, 8, 1, out2);
	phex ("REF catena(g=8,lam=1) = ", out2, DIGEST);
	printf ("catena different lambda -> different output = %s\n", memcmp (out, out2, DIGEST) != 0 ? "YES" : "NO");
	catena_brg ((const unsigned char*) PW, pwl, salt, 16, 10, 3, out2);
	phex ("REF catena(g=10,lam=3) = ", out2, DIGEST);
	printf ("catena different garlic -> different output = %s\n", memcmp (out, out2, DIGEST) != 0 ? "YES" : "NO");

	catena_brg ((const unsigned char*) PW, pwl, salt, 16, 8, 3, out2);
	printf ("catena deterministic = %s\n", memcmp (out, out2, DIGEST) == 0 ? "YES" : "NO");
	{ unsigned char z[16]; memset (z, 0, 16); catena_brg ((const unsigned char*) PW, pwl, z, 16, 8, 3, out2);
	  printf ("catena different salt -> different output = %s\n", memcmp (out, out2, DIGEST) != 0 ? "YES" : "NO"); }
	return 0;
}
