/*
 * duress_dudect_test.c — timing-leakage screen for the REAL DuressTokenMatch (ROI item 34).
 *
 * DuressTokenMatch compares a derived duress tag against the stored one. If that compare short-circuits
 * on the first differing byte, its running time leaks HOW MANY leading bytes matched — a classic
 * tag-comparison side channel that lets an attacker forge a valid tag byte-by-byte. The real code is
 * an OR-accumulate with no early exit; this is the measurement that backs the "constant-time" claim.
 *
 * Self-validating dudect (Reparaz-Balasch-Yarom Welch t-test), same framework as shamir_dudect_test.c:
 *   class 0 = pairs that differ in the FIRST byte (an early-exit compare returns immediately);
 *   class 1 = pairs identical except the LAST byte (an early-exit compare scans the whole tag).
 * A deliberately-leaky early-exit reference MUST be flagged (|t| large) and the real DuressTokenMatch
 * MUST be cleared (|t| small). Asserting that CONTRAST — not an absolute cycle count — keeps the
 * pass/fail stable across machines. dudect is a screen, not a proof of constant-timeness.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "Common/DuressToken.h"

static uint64_t g_s = 0xdead1357abcd2468ULL;
static uint64_t xr (void) { uint64_t x=g_s; x^=x<<13; x^=x>>7; x^=x<<17; g_s=x; return x; }

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static uint64_t cycles (void) { return __rdtsc(); }
#else
#include <time.h>
static uint64_t cycles (void) { struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t); return (uint64_t) t.tv_sec * 1000000000ull + t.tv_nsec; }
#endif

#define TAGLEN 32
#define BATCH  256
#define NMEAS  150000

/* leaky reference: early-exit compare (returns as soon as a byte differs) */
static int match_leaky (const unsigned char *a, const unsigned char *b, int len)
{
	int i;
	for (i = 0; i < len; i++) if (a[i] != b[i]) return 0;
	return 1;
}

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

static double screen_match (int (*mfn)(const unsigned char *, const unsigned char *, int))
{
	static uint64_t m0[NMEAS], m1[NMEAS];
	int n0 = 0, n1 = 0, i, j;
	volatile int sink = 0;
	static unsigned char A[BATCH][TAGLEN], B[BATCH][TAGLEN];

	for (i = 0; i < 50000; i++) { unsigned char x[TAGLEN], y[TAGLEN]; memset(x,0,TAGLEN); memset(y,0,TAGLEN); sink ^= mfn(x,y,TAGLEN); }

	for (i = 0; i < NMEAS; i++)
	{
		int cls = (int) (xr() & 1);
		uint64_t t0, t1; int acc = 0;

		/* prepare inputs OUTSIDE the timed region. Both classes: a random base tag; b == a except one
		   differing byte, placed at index 0 (class 0, early) or TAGLEN-1 (class 1, late). */
		for (j = 0; j < BATCH; j++) {
			int k; for (k = 0; k < TAGLEN; k++) { unsigned char v = (unsigned char) xr(); A[j][k] = v; B[j][k] = v; }
			if (cls == 0) B[j][0]        ^= 0x01;
			else          B[j][TAGLEN-1] ^= 0x01;
		}

		t0 = cycles ();
		for (j = 0; j < BATCH; j++) acc += mfn (A[j], B[j], TAGLEN);
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
	double tReal, tLeaky;

	/* sanity: both implementations agree on the boolean result for the fuzzed inputs */
	{
		int i, mism = 0;
		for (i = 0; i < 100000; i++) {
			unsigned char a[TAGLEN], b[TAGLEN]; int k;
			for (k=0;k<TAGLEN;k++){ unsigned char v=(unsigned char)xr(); a[k]=v; b[k]=v; }
			if (xr() & 1) b[(int)(xr()%TAGLEN)] ^= (unsigned char)(1 + (xr()%255));
			if ((DuressTokenMatch(a,b,TAGLEN)!=0) != (match_leaky(a,b,TAGLEN)!=0)) mism++;
		}
		printf ("DuressTokenMatch vs leaky agree on all results = %s\n", mism==0 ? "YES" : "NO");
	}

	tLeaky = screen_match (match_leaky);
	tReal  = screen_match (DuressTokenMatch);

	printf ("dudect max|t|  real DuressTokenMatch (OR-accumulate) = %.2f\n", tReal);
	printf ("dudect max|t|  leaky early-exit compare            = %.2f\n", tLeaky);
	/* self-validating: the screen must FLAG the leaky compare and CLEAR the real one. */
	printf ("screen flags the leaky compare (|t| > 15)          = %s\n", tLeaky > 15.0 ? "YES" : "NO");
	printf ("real compare cleared (|t| < 10)                    = %s\n", tReal < 10.0 ? "YES" : "NO");
	printf ("leaky/real contrast >= 4x                          = %s\n", tLeaky >= 4.0 * (tReal < 1.0 ? 1.0 : tReal) ? "YES" : "NO");

	if (tLeaky > 15.0 && tReal < 10.0 && tLeaky >= 4.0 * (tReal < 1.0 ? 1.0 : tReal)) {
		printf ("PASS: dudect flags the leaky tag compare and clears the real constant-time DuressTokenMatch\n");
		return 0;
	}
	printf ("FAIL: dudect screen inconclusive (tReal=%.2f tLeaky=%.2f)\n", tReal, tLeaky);
	return 1;
}
