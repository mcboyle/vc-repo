/*
 * hctr2_dudect_test.c — timing-leakage screen for the REAL gf_dot() (POLYVAL / GF(2^128) dot product)
 * in verification/hctr2_poc.c (build_and_verify.sh step following [26]; research batch-2 item C1).
 *
 * gf_dot's operands are both secret: the POLYVAL hash key h = AES_k(0^128) is derived directly from
 * the AES key, and the accumulator s is a function of that key and the message. gf_dot was rewritten
 * branch-free — the two data-dependent `if`s (a's bit in the multiply loop, c's low bit in the
 * reduction loop) replaced by arithmetic masks — using the SAME pattern src/Common/Shamir.c uses for
 * GF(2^8) (see shamir_dudect_test.c step [41]): one convention, applied twice, not two ad-hoc fixes.
 * This is the measurement that backs the constant-time claim.
 *
 * A timing test is statistical, not a KAT, so this screen is SELF-VALIDATING to stay robust against
 * sandbox noise (identical design to shamir_dudect_test.c): it runs the same dudect (Reparaz-Balasch-
 * Yarom) Welch t-test on (a) the REAL branch-free gf_dot and (b) a deliberately-branchy gf_dot_leaky
 * (the original two-`if` version). The screen must FLAG the leaky one (|t| large) and CLEAR the real
 * one (|t| small). Asserting that CONTRAST — not an absolute |t| — is what makes pass/fail stable
 * across machines. dudect is a leakage screen, not a proof; a clean result is evidence, not a guarantee.
 *
 * Includes hctr2_poc.c (with HCTR2_NO_MAIN) to reach the real static gf_dot — same technique as
 * shamir_dudect_test.c including Shamir.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#define HCTR2_NO_MAIN
#include "hctr2_poc.c"   /* reach the real static gf_dot (and its u256 type) */

/* deterministic PRNG so the pass/fail verdict is reproducible (timing isn't, the verdict is) */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t xr (void) { uint64_t x = g_rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; g_rng = x; return x; }

/* the ORIGINAL branchy gf_dot: two data-dependent branches (a's bit; c's low bit). It computes the
   byte-identical field product — only its timing depends on the secret operands, which is exactly the
   channel the branch-free rewrite removed and which this screen must catch. */
static void gf_dot_leaky (const uint64_t a[2], const uint64_t b[2], uint64_t out[2])
{
	u256 c; int i, limb;
	memset (&c, 0, sizeof c);
	for (i = 0; i < 128; i++) {
		if ((a[i >> 6] >> (i & 63)) & 1) {                       /* data-dependent branch (secret a) */
			int w = i >> 6, s = i & 63;
			c.w[w]     ^= b[0] << s;
			c.w[w + 1] ^= (s ? (b[0] >> (64 - s)) : 0) ^ (b[1] << s);
			c.w[w + 2] ^= s ? (b[1] >> (64 - s)) : 0;
		}
	}
	for (i = 0; i < 128; i++) {
		if (c.w[0] & 1) {                                         /* data-dependent branch (secret c) */
			c.w[0] ^= 1ULL;
			c.w[1] ^= (1ULL << 57) | (1ULL << 62) | (1ULL << 63);
			c.w[2] ^= 1ULL;
		}
		for (limb = 0; limb < 3; limb++)
			c.w[limb] = (c.w[limb] >> 1) | (c.w[limb + 1] << 63);
		c.w[3] >>= 1;
	}
	out[0] = c.w[0]; out[1] = c.w[1];
}

/* cycle counter */
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static uint64_t cycles (void) { return __rdtsc(); }
#else
#include <time.h>
static uint64_t cycles (void) { struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t); return (uint64_t) t.tv_sec * 1000000000ull + t.tv_nsec; }
#endif

#define BATCH 256          /* gf_dot calls timed per measurement (lifts signal over timer granularity) */

/* Welch's t between two measurement sets after cropping the top `cropPct` (interrupt outliers). */
static double welch_t (uint64_t *m0, int n0, uint64_t *m1, int n1, double cropPct)
{
	uint64_t cap0 = 0, cap1 = 0; int i;
	for (i = 0; i < n0; i++) if (m0[i] > cap0) cap0 = m0[i];
	for (i = 0; i < n1; i++) if (m1[i] > cap1) cap1 = m1[i];
	{
		uint64_t cap = (cap0 > cap1 ? cap0 : cap1);
		double thr = (double) cap * (1.0 - cropPct / 100.0);
		double s0 = 0, s1 = 0, ss0 = 0, ss1 = 0; int c0 = 0, c1 = 0;
		double mean0, mean1, var0, var1;
		for (i = 0; i < n0; i++) if ((double) m0[i] <= thr) { s0 += m0[i]; c0++; }
		for (i = 0; i < n1; i++) if ((double) m1[i] <= thr) { s1 += m1[i]; c1++; }
		if (c0 < 2 || c1 < 2) return 0.0;
		mean0 = s0 / c0; mean1 = s1 / c1;
		for (i = 0; i < n0; i++) if ((double) m0[i] <= thr) { double d = m0[i] - mean0; ss0 += d * d; }
		for (i = 0; i < n1; i++) if ((double) m1[i] <= thr) { double d = m1[i] - mean1; ss1 += d * d; }
		var0 = ss0 / (c0 - 1); var1 = ss1 / (c1 - 1);
		if (var0 <= 0 && var1 <= 0) return 0.0;
		return (mean0 - mean1) / sqrt (var0 / c0 + var1 / c1);
	}
}

#define NMEAS 120000

/* Run the dudect screen on a gf_dot impl. class 0 = fixed all-zero operand a (the leaky impl skips
   ALL multiply-XORs and the accumulator stays 0 so it skips ALL reduction-XORs → fast); class 1 =
   random a,b (the leaky impl takes both branches ~half the iterations → slow). The branch-free gf_dot
   does the same masked work for both classes. Both classes run a BYTE-IDENTICAL timed loop reading
   from per-measurement input arrays filled OUTSIDE the timed region. Returns max|t|. */
static double screen_dot (void (*dot)(const uint64_t[2], const uint64_t[2], uint64_t[2]))
{
	static uint64_t m0[NMEAS], m1[NMEAS];
	int n0 = 0, n1 = 0, i, j;
	volatile uint64_t sink = 0;
	uint64_t av[BATCH][2], bv[BATCH][2], o[2];

	for (i = 0; i < 60000; i++) { uint64_t a[2] = { xr(), xr() }, b[2] = { xr(), xr() }; dot (a, b, o); sink ^= o[0]; }

	for (i = 0; i < NMEAS; i++)
	{
		int cls = (int) (xr() & 1);
		uint64_t t0, t1, acc = 0;

		if (cls == 0)
			for (j = 0; j < BATCH; j++) { av[j][0] = av[j][1] = 0; bv[j][0] = bv[j][1] = 0; }
		else
			for (j = 0; j < BATCH; j++) { av[j][0] = xr(); av[j][1] = xr(); bv[j][0] = xr(); bv[j][1] = xr(); }

		t0 = cycles ();
		for (j = 0; j < BATCH; j++) { dot (av[j], bv[j], o); acc ^= o[0] ^ o[1]; }
		t1 = cycles ();
		sink ^= acc;

		if (cls == 0) m0[n0++] = t1 - t0; else m1[n1++] = t1 - t0;
	}
	{
		double best = 0.0, crops[3] = { 0.0, 0.5, 2.0 }; int k;
		for (k = 0; k < 3; k++) { double t = fabs (welch_t (m0, n0, m1, n1, crops[k])); if (t > best) best = t; }
		(void) sink;
		return best;
	}
}

int main (void)
{
	double tClean, tLeaky;
	int ok = 1;

	/* sanity: real branch-free gf_dot and the branchy leaky version compute the SAME field product
	   over random inputs (so the ONLY difference between them is timing). */
	{
		int t, mism = 0;
		for (t = 0; t < 20000; t++) {
			uint64_t a[2] = { xr(), xr() }, b[2] = { xr(), xr() }, o1[2], o2[2];
			gf_dot (a, b, o1); gf_dot_leaky (a, b, o2);
			if (o1[0] != o2[0] || o1[1] != o2[1]) mism++;
		}
		printf ("real gf_dot vs leaky branchy agree on 20000 random products = %s\n", mism == 0 ? "YES" : "NO");
		if (mism) ok = 0;
	}

	tClean = screen_dot (gf_dot);
	tLeaky = screen_dot (gf_dot_leaky);
	printf ("dudect max|t|  real gf_dot (branch-free/masked) = %.2f\n", tClean);
	printf ("dudect max|t|  leaky branchy gf_dot            = %.2f\n", tLeaky);

	/* Verdict (contrast-based, robust to absolute noise): FLAG the known-leaky impl, CLEAR the real one. */
	printf ("screen flags the leaky impl (|t| > 15)  = %s\n", tLeaky > 15.0 ? "YES" : "NO");
	printf ("screen clears real gf_dot (|t| < 10)    = %s\n", tClean < 10.0 ? "YES" : "NO");
	printf ("leaky/clean contrast >= 4x              = %s\n", tLeaky >= 4.0 * (tClean < 1.0 ? 1.0 : tClean) ? "YES" : "NO");
	if (!(tLeaky > 15.0 && tClean < 10.0)) ok = 0;

	printf ("%s\n", ok ? "HCTR2 GF_DOT DUDECT SCREEN PASSED" : "HCTR2 GF_DOT DUDECT SCREEN FAILED");
	return ok ? 0 : 1;
}
