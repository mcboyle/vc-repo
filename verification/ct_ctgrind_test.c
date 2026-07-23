/*
 * ct_ctgrind_test.c — ctgrind-style constant-time check for the project's masked secret-dependent
 * primitives, using valgrind/memcheck (research batch-3 R17 scaffold).
 *
 * dudect (steps [41]/[.. ]/[82]) is a black-box *timing* screen; it cannot see WHICH instruction leaks,
 * and it measures in a shared VM. This is the complementary white-box check R17 Q1/Q3 ask about: mark the
 * SECRET operands as "undefined" (VALGRIND_MAKE_MEM_UNDEFINED) and run the primitive under memcheck. If
 * the compiled code branches on, or indexes memory with, any secret-derived bit, memcheck reports
 * "Conditional jump or move depends on uninitialised value" / "use of uninitialised value" — so a CLEAN
 * run is direct evidence that the arithmetic masking survived the compiler with no secret-dependent
 * control flow (the exact failure mode — cmov-not-guaranteed, -O2/-O3 divergence, LTO — R17 raises).
 *
 * This binary is SELF-VALIDATING like the dudect screens: it runs the check on (a) the REAL masked
 * primitives and (b) a deliberately branchy leaky copy. Under valgrind the harness asserts memcheck
 * FLAGS the leaky one and CLEARS the real ones; the driver (build_and_verify.sh) greps valgrind's error
 * count. Built WITHOUT valgrind it still runs (the client requests are no-ops) and just self-checks
 * functional agreement, so the suite step degrades to a skip when valgrind is absent.
 *
 * Includes the real static primitives (Shamir.c gf_mul/gf_inv; a copy of the masked gf_dot that is kept
 * byte-identical to verification/hctr2_poc.c) — same include technique as the dudect harnesses.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if defined(CT_USE_VALGRIND)
#  include <valgrind/memcheck.h>
#  define SECRET(p, n)  VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#  define PUBLIC(p, n)  VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#  define SECRET(p, n)  ((void)0)
#  define PUBLIC(p, n)  ((void)0)
#endif

#include "Shamir.c"   /* real static gf_mul / gf_inv (branchless, masked) */

/* ---- masked gf_dot: kept byte-identical to verification/hctr2_poc.c ---- */
typedef struct { uint64_t w[4]; } u256;
static void gf_dot (const uint64_t a[2], const uint64_t b[2], uint64_t out[2]) {
	u256 c; int i, limb; memset (&c, 0, sizeof c);
	for (i = 0; i < 128; i++) {
		uint64_t m = 0ULL - ((a[i >> 6] >> (i & 63)) & 1ULL);
		int w = i >> 6, s = i & 63;
		c.w[w]     ^= (b[0] << s) & m;
		c.w[w + 1] ^= (((s ? (b[0] >> (64 - s)) : 0) ^ (b[1] << s)) & m);
		c.w[w + 2] ^= ((s ? (b[1] >> (64 - s)) : 0) & m);
	}
	for (i = 0; i < 128; i++) {
		uint64_t r = 0ULL - (c.w[0] & 1ULL);
		c.w[0] ^= 1ULL & r;
		c.w[1] ^= (((1ULL << 57) | (1ULL << 62) | (1ULL << 63)) & r);
		c.w[2] ^= 1ULL & r;
		for (limb = 0; limb < 3; limb++) c.w[limb] = (c.w[limb] >> 1) | (c.w[limb + 1] << 63);
		c.w[3] >>= 1;
	}
	out[0] = c.w[0]; out[1] = c.w[1];
}

/* ---- deliberately-branchy leaky copies (secret-dependent control flow) ---- */
static unsigned char gf_mul_leaky (unsigned char a, unsigned char b) {
	unsigned char p = 0;
	while (b) { if (b & 1) p ^= a;                       /* branch on secret b */
		{ unsigned hi = a & 0x80; a = (unsigned char)((a << 1) & 0xff); if (hi) a ^= 0x1b; }
		b = (unsigned char)(b >> 1); }
	return p;
}
static void gf_dot_leaky (const uint64_t a[2], const uint64_t b[2], uint64_t out[2]) {
	u256 c; int i, limb; memset (&c, 0, sizeof c);
	for (i = 0; i < 128; i++) {
		if ((a[i >> 6] >> (i & 63)) & 1) {               /* branch on secret a */
			int w = i >> 6, s = i & 63;
			c.w[w]     ^= b[0] << s;
			c.w[w + 1] ^= (s ? (b[0] >> (64 - s)) : 0) ^ (b[1] << s);
			c.w[w + 2] ^= s ? (b[1] >> (64 - s)) : 0;
		}
	}
	for (i = 0; i < 128; i++) {
		if (c.w[0] & 1) { c.w[0] ^= 1ULL; c.w[1] ^= (1ULL<<57)|(1ULL<<62)|(1ULL<<63); c.w[2] ^= 1ULL; }
		for (limb = 0; limb < 3; limb++) c.w[limb] = (c.w[limb] >> 1) | (c.w[limb + 1] << 63);
		c.w[3] >>= 1;
	}
	out[0] = c.w[0]; out[1] = c.w[1];
}

/* volatile sinks so the compiler cannot elide the primitive under test */
static volatile unsigned char g_sink8;
static volatile uint64_t      g_sink64;

int main (int argc, char **argv)
{
	int leaky = (argc > 1 && strcmp (argv[1], "leaky") == 0);

	/* functional agreement first (so the ONLY difference the ct check sees is control flow) */
	{
		int a, b, mism = 0;
		for (a = 0; a < 256; a++) for (b = 0; b < 256; b++)
			if (gf_mul ((unsigned char)a, (unsigned char)b) != gf_mul_leaky ((unsigned char)a, (unsigned char)b)) mism++;
		printf ("gf_mul vs leaky agree on 65536 products = %s\n", mism ? "NO" : "YES");
	}

	/* --- gf_mul / gf_inv over GF(2^8): poison the secret operand, exercise every value --- */
	{
		int i; unsigned char x, y;
		for (i = 0; i < 256; i++) {
			x = (unsigned char) i; y = (unsigned char)(i * 7 + 1);
			SECRET (&x, 1); SECRET (&y, 1);
			g_sink8 = leaky ? gf_mul_leaky (x, y) : gf_mul (x, y);
			g_sink8 = gf_inv (x);              /* gf_inv is fixed-schedule; always the real one */
			PUBLIC (&x, 1); PUBLIC (&y, 1);
		}
	}

	/* --- gf_dot over GF(2^128): poison both 128-bit operands --- */
	{
		uint64_t a[2], b[2], o[2]; int t;
		for (t = 0; t < 64; t++) {
			a[0] = (uint64_t)(t*2654435761u); a[1] = (uint64_t)(t*40503u+7);
			b[0] = (uint64_t)(t*2246822519u); b[1] = (uint64_t)(t*3266489917u+11);
			SECRET (a, sizeof a); SECRET (b, sizeof b);
			if (leaky) gf_dot_leaky (a, b, o); else gf_dot (a, b, o);
			PUBLIC (o, sizeof o);           /* de-poison the output so the sink read is clean */
			g_sink64 ^= o[0] ^ o[1];
		}
	}

	printf ("%s primitives exercised under memcheck poisoning\n", leaky ? "LEAKY" : "REAL");
	return 0;
}
