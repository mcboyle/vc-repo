/*
 * keyslot_dudect_test.c — timing-leakage screen for the keyslot constant-time tag compare
 * (build_and_verify.sh step [46]; IDEAS-BACKLOG "Constant-time verification in CI — over the Shamir
 * AND keyslot paths"). Step [41] screened the Shamir GF(2^8) primitives; this screens the keyslot
 * path's constant-time comparison, KeyslotConstTimeEqual (the MAC-as-slot-selector: a data-dependent
 * early-out here would leak which slot / how many bytes of a tag matched).
 *
 * Same dudect-style (Reparaz-Balasch-Yarom) Welch t-test, and SELF-VALIDATING like step [41]: the
 * screen runs on the real KeyslotConstTimeEqual AND on a leaky early-out memcmp-style compare, and
 * must FLAG the leaky one while CLEARING the constant-time one. class 0 = buffers that differ in the
 * FIRST byte (leaky returns immediately); class 1 = buffers that differ only in the LAST byte (leaky
 * scans the whole length). A constant-time compare takes the same time for both.
 *
 * Includes Keyslot.c to reach the real KeyslotConstTimeEqual (built with VC_ENABLE_KEYSLOTS).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "Common/Keyslot.h"

int KeyslotConstTimeEqual (const unsigned char *a, const unsigned char *b, int len);   /* from Keyslot.c */

/* a deliberately-LEAKY compare: returns on the first differing byte (like memcmp==0). */
static int leaky_equal (const unsigned char *a, const unsigned char *b, int len)
{
	int i;
	for (i = 0; i < len; i++)
		if (a[i] != b[i]) return 0;   /* data-dependent early-out */
	return 1;
}

static uint64_t g_rng = 0x243F6A8885A308D3ULL;
static uint64_t xr (void) { uint64_t x = g_rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; g_rng = x; return x; }

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static uint64_t cycles (void) { return __rdtsc(); }
#else
#include <time.h>
static uint64_t cycles (void) { struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t); return (uint64_t) t.tv_sec * 1000000000ull + t.tv_nsec; }
#endif

#define TAGLEN 32
#define BATCH  512
#define NMEAS  200000

static double welch_t (uint64_t *m0, int n0, uint64_t *m1, int n1, double cropPct)
{
	uint64_t cap = 0; int i;
	for (i = 0; i < n0; i++) if (m0[i] > cap) cap = m0[i];
	for (i = 0; i < n1; i++) if (m1[i] > cap) cap = m1[i];
	{
		double thr = (double) cap * (1.0 - cropPct / 100.0);
		double s0 = 0, s1 = 0, ss0 = 0, ss1 = 0, mean0, mean1, var0, var1; int c0 = 0, c1 = 0;
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

/* class 0: pairs differing in byte 0; class 1: pairs differing only in the last byte. Identical timed
   loop; inputs prepared outside the timed region. */
static double screen_eq (int (*eq)(const unsigned char*, const unsigned char*, int))
{
	static uint64_t m0[NMEAS], m1[NMEAS];
	int n0 = 0, n1 = 0, i, j;
	volatile int sink = 0;
	unsigned char a[BATCH][TAGLEN], b[BATCH][TAGLEN];

	for (i = 0; i < 50000; i++) { unsigned char x[TAGLEN], y[TAGLEN]; int k; for (k=0;k<TAGLEN;k++){x[k]=(unsigned char)xr();y[k]=x[k];} y[0]^=1; sink ^= eq (x, y, TAGLEN); }

	for (i = 0; i < NMEAS; i++)
	{
		int cls = (int) (xr() & 1);
		uint64_t t0, t1; int acc = 0;
		for (j = 0; j < BATCH; j++) { int k; for (k = 0; k < TAGLEN; k++) { a[j][k] = (unsigned char) xr(); b[j][k] = a[j][k]; }
			if (cls == 0) b[j][0] ^= 0xFF; else b[j][TAGLEN - 1] ^= 0xFF; }
		t0 = cycles ();
		for (j = 0; j < BATCH; j++) acc ^= eq (a[j], b[j], TAGLEN);
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

	/* sanity: both agree on equal/unequal verdicts over random inputs */
	{
		int i, mism = 0;
		for (i = 0; i < 100000; i++)
		{
			unsigned char x[TAGLEN], y[TAGLEN]; int k, flip = (int) (xr() % (TAGLEN + 1));
			for (k = 0; k < TAGLEN; k++) { x[k] = (unsigned char) xr(); y[k] = x[k]; }
			if (flip < TAGLEN) y[flip] ^= 0xFF;
			if ((KeyslotConstTimeEqual (x, y, TAGLEN) != 0) != (leaky_equal (x, y, TAGLEN) != 0)) mism++;
		}
		printf ("const-time vs leaky compare agree on all verdicts = %s\n", mism == 0 ? "YES" : "NO");
		if (mism) ok = 0;
	}

	tClean = screen_eq (KeyslotConstTimeEqual);
	tLeaky = screen_eq (leaky_equal);
	printf ("dudect max|t|  KeyslotConstTimeEqual = %.2f\n", tClean);
	printf ("dudect max|t|  leaky early-out compare = %.2f\n", tLeaky);

	printf ("screen flags the leaky compare (|t| > 15) = %s\n", tLeaky > 15.0 ? "YES" : "NO");
	printf ("screen clears KeyslotConstTimeEqual (|t| < 10) = %s\n", tClean < 10.0 ? "YES" : "NO");
	if (!(tLeaky > 15.0 && tClean < 10.0)) ok = 0;

	printf ("%s\n", ok ? "KEYSLOT DUDECT SCREEN PASSED" : "KEYSLOT DUDECT SCREEN FAILED");
	return ok ? 0 : 1;
}
