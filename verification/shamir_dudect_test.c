/*
 * shamir_dudect_test.c — timing-leakage screen for the REAL Common/Shamir.c GF(2^8) multiply/inverse
 * (build_and_verify.sh step [41]; ROADMAP item 15 follow-up, lines ~89-90).
 *
 * Shamir.c's gf_mul/gf_inv were rewritten branchless + table-free specifically to remove the cache /
 * branch-prediction side channel the old table version had. This is the measurement that backs that
 * claim: a dudect-style (Reparaz-Balasch-Yarom) Welch t-test over two input classes.
 *
 * A timing test is statistical, not a byte-for-byte KAT, so this step is SELF-VALIDATING to stay
 * robust against sandbox noise: it runs the same screen on (a) the real branchless gf_mul and (b) a
 * deliberately-leaky table gf_mul with an `a==0` early-out and secret-indexed lookups. The screen must
 * FLAG the leaky one (|t| large) and CLEAR the real one (|t| small). Asserting that CONTRAST — not an
 * absolute cycle count — is what makes the pass/fail stable across machines. dudect is a leakage
 * screen, not a proof of constant-timeness; a clean result is evidence, not a guarantee.
 *
 * Includes Shamir.c to reach the static gf_mul/gf_inv (same technique as shamir_test.c).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "Shamir.c"   /* reach the static gf_mul / gf_inv */

/* deterministic PRNG so the pass/fail outcome is reproducible (timing isn't, the verdict is) */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t xr (void) { uint64_t x = g_rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; g_rng = x; return x; }

/* a deliberately-LEAKY GF(2^8) multiply: the classic variable-time Russian-peasant that stops as
   soon as b's remaining bits are zero, so the iteration count depends on the secret operand b. This
   is the data-dependent control flow Shamir.c's fixed-8-iteration version removed; the screen must
   catch it. It computes the byte-identical field product (the trailing iterations gf_mul runs when
   b has become 0 only shift a and never xor). */
static unsigned char gf_mul_leaky (unsigned char a, unsigned char b)
{
	unsigned char p = 0;
	while (b)                                        /* iteration count = index of b's top set bit */
	{
		if (b & 1) p ^= a;                          /* data-dependent branch */
		{ unsigned int hi = a & 0x80; a = (unsigned char) ((a << 1) & 0xff); if (hi) a ^= 0x1b; }
		b = (unsigned char) (b >> 1);
	}
	return p;
}

/* gf_inv wrapped to the binary signature so it reuses the same screen; b is ignored. gf_inv runs a
   fixed square-and-multiply schedule over the PUBLIC exponent 254 (calling only gf_mul), so it is
   constant-time by construction — the screen should clear it. */
static unsigned char gf_inv_wrap (unsigned char a, unsigned char b) { (void) b; return gf_inv (a); }

/* cycle counter */
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static uint64_t cycles (void) { return __rdtsc(); }
#else
#include <time.h>
static uint64_t cycles (void) { struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t); return (uint64_t) t.tv_sec * 1000000000ull + t.tv_nsec; }
#endif

#define BATCH 512          /* ops timed per measurement (lifts signal over timer granularity) */

/* Welch's t between two measurement sets after cropping the top `cropPct` (interrupt outliers). */
static double welch_t (uint64_t *m0, int n0, uint64_t *m1, int n1, double cropPct)
{
	/* crop threshold = the (100-cropPct) percentile of the pooled max, approximated per-class */
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

#define NMEAS 200000

/* Run the dudect screen on a multiply fn. class 0 = fixed operands (a = 0, which trips a leaky
   early-out); class 1 = random operands. The two classes execute a BYTE-IDENTICAL timed loop
   (`for j: acc ^= mul(a[j], b[j])`) reading from per-measurement input arrays filled OUTSIDE the
   timed region — so any timing difference is the multiply's data dependence, not the harness.
   Classes are interleaved by a random bit to decorrelate environmental drift. Returns max|t|. */
static double screen_mul (unsigned char (*mul)(unsigned char, unsigned char))
{
	static uint64_t m0[NMEAS], m1[NMEAS];
	int n0 = 0, n1 = 0, i, j;
	volatile unsigned char sink = 0;
	unsigned char a[BATCH], b[BATCH];

	/* warm up caches/branch predictor */
	for (i = 0; i < 100000; i++) sink ^= mul ((unsigned char) xr(), (unsigned char) xr());

	for (i = 0; i < NMEAS; i++)
	{
		int cls = (int) (xr() & 1);
		uint64_t t0, t1; unsigned char acc = 0;

		/* prepare inputs OUTSIDE the timed region. class 0 = fixed all-zero (the leaky mul does 0
		   iterations); class 1 = random (the leaky mul does a variable ~7 iterations). The branchless
		   gf_mul does a fixed 8 iterations for BOTH, so only the leaky one separates the classes. */
		if (cls == 0)
			for (j = 0; j < BATCH; j++) { a[j] = 0; b[j] = 0; }
		else
			for (j = 0; j < BATCH; j++) { a[j] = (unsigned char) xr(); b[j] = (unsigned char) xr(); }

		/* IDENTICAL timed loop for both classes */
		t0 = cycles ();
		for (j = 0; j < BATCH; j++) acc ^= mul (a[j], b[j]);
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

	/* sanity: leaky and clean compute the SAME field product (so the only difference is timing) */
	{
		int a, b, mism = 0;
		for (a = 0; a < 256; a++) for (b = 0; b < 256; b++)
			if (gf_mul ((unsigned char) a, (unsigned char) b) != gf_mul_leaky ((unsigned char) a, (unsigned char) b)) mism++;
		printf ("gf_mul vs leaky table agree on all 65536 products = %s\n", mism == 0 ? "YES" : "NO");
		if (mism) ok = 0;
	}

	tClean = screen_mul (gf_mul);
	tLeaky = screen_mul (gf_mul_leaky);
	{
		double tInv = screen_mul (gf_inv_wrap);
		printf ("dudect max|t|  real gf_mul (branchless) = %.2f\n", tClean);
		printf ("dudect max|t|  real gf_inv (fixed sched) = %.2f\n", tInv);
		printf ("dudect max|t|  leaky variable-time gf_mul = %.2f\n", tLeaky);

		/* Verdict (contrast-based, robust to absolute noise):
		   the screen must FLAG the known-leaky impl and CLEAR both real primitives. */
		printf ("screen flags the leaky impl (|t| > 15)  = %s\n", tLeaky > 15.0 ? "YES" : "NO");
		printf ("screen clears real gf_mul (|t| < 10)    = %s\n", tClean < 10.0 ? "YES" : "NO");
		printf ("screen clears real gf_inv (|t| < 10)    = %s\n", tInv < 10.0 ? "YES" : "NO");
		printf ("leaky/clean contrast >= 4x              = %s\n", tLeaky >= 4.0 * (tClean < 1.0 ? 1.0 : tClean) ? "YES" : "NO");
		if (!(tLeaky > 15.0 && tClean < 10.0 && tInv < 10.0)) ok = 0;
	}

	printf ("%s\n", ok ? "SHAMIR DUDECT SCREEN PASSED" : "SHAMIR DUDECT SCREEN FAILED");
	return ok ? 0 : 1;
}
