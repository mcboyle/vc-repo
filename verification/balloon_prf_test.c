/*
 * balloon_prf_test.c — the SHIPPING derive_key_balloon in Common/Pkcs5.c, compiled as the real
 * Pkcs5.c translation unit (step [11]'s pattern) and driven against balloon_prf_reference.py
 * (build_and_verify.sh step [38]; docs/BALLOON-SPEC.md selectable-PRF integration).
 *
 * REF lines (diffed byte-for-byte vs the independent Python): dk for dklen 32 (the Balloon output
 * K directly), 64 and 192 (the counter expansion, incl. BALLOON_HEADER_KEYDATA_SIZE), and the
 * PIM -> (tcost, spaceKib) resolver incl. the explicit override. The Python side additionally
 * asserts its Balloon core reproduces the step-[16] anchor 635ebeac..., chaining this function to
 * the proven PoC construction. Non-REF checks: the abort flag zeroes dk; a benchmark vs the real
 * derive_key_argon2 (informational).
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "Tcdefs.h"
#include "Common/Pkcs5.h"
#include "Common/Crypto.h"

static void phex (const char *label, const unsigned char *p, int n)
{
	int i;
	printf ("%s", label);
	for (i = 0; i < n; i++) printf ("%02x", p[i]);
	printf ("\n");
}

static double ms_since (clock_t t0) { return (double) (clock () - t0) * 1000.0 / CLOCKS_PER_SEC; }

int main (void)
{
	const char *PW = "correct horse battery staple";
	unsigned char salt[16], dk[192], dk2[192];
	int i, pwl = (int) strlen (PW);
	uint32 t, s;

	for (i = 0; i < 16; i++) salt[i] = (unsigned char) ((i * 5 + 1) & 0xff);

	/* dklen = 32: K directly (spaceKib=1 -> n=32 blocks) */
	if (derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 1, dk, 32, NULL) != 0)
		{ printf ("derive failed\n"); return 1; }
	phex ("REF balloon dk32(skib=1,t=3) = ", dk, 32);

	/* dklen = 64 and 192: counter expansion of K */
	if (derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 1, dk, 64, NULL) != 0)
		{ printf ("derive failed\n"); return 1; }
	phex ("REF balloon dk64(skib=1,t=3) = ", dk, 64);
	if (derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 1, dk, 192, NULL) != 0)
		{ printf ("derive failed\n"); return 1; }
	phex ("REF balloon dk192(skib=1,t=3) = ", dk, 192);

	/* dk32 must be the prefix of dk64/dk192? NO - expansion only applies past 32; dk32 == K and
	   dk64[0..32) is expansion block 1, deliberately != K. Determinism instead: */
	if (derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 1, dk2, 192, NULL) != 0)
		{ printf ("derive failed\n"); return 1; }
	printf ("deterministic (same inputs -> same dk192) = %s\n", memcmp (dk, dk2, 192) == 0 ? "YES" : "NO");

	/* cost separation */
	derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 4, 1, dk2, 192, NULL);
	printf ("different tcost -> different dk = %s\n", memcmp (dk, dk2, 192) != 0 ? "YES" : "NO");
	derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 2, dk2, 192, NULL);
	printf ("different space -> different dk = %s\n", memcmp (dk, dk2, 192) != 0 ? "YES" : "NO");

	/* PIM resolver + override (REF-diffed against the python formula) */
	BalloonSetParamsOverride (0, 0);
	BalloonGetResolvedParams (0, &t, &s);   printf ("REF balloon params pim=0 = %u,%u\n", t, s);
	BalloonGetResolvedParams (1, &t, &s);   printf ("REF balloon params pim=1 = %u,%u\n", t, s);
	BalloonGetResolvedParams (13, &t, &s);  printf ("REF balloon params pim=13 = %u,%u\n", t, s);
	BalloonGetResolvedParams (485, &t, &s); printf ("REF balloon params pim=485 = %u,%u\n", t, s);
	BalloonSetParamsOverride (7, 4096);
	BalloonGetResolvedParams (13, &t, &s);  printf ("REF balloon params override = %u,%u\n", t, s);
	BalloonSetParamsOverride (0, 0);

	/* abort: raised flag must fail with -2 and zero dk (behavioural; not python-diffed) */
	{
		long volatile abortFlag = 1;
		int r = derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 1, dk2, 192, &abortFlag);
		int allz = 1;
		for (i = 0; i < 192; i++) if (dk2[i]) allz = 0;
		printf ("abort honored (rc=-2, dk zeroed) = %s\n", (r == -2 && allz) ? "YES" : "NO");
	}

	/* benchmark vs the real Argon2id (informational; both are the real compiled objects) */
	{
		clock_t t0;
		int it = 0, mc = 0;
		double msB, msA;
		t0 = clock ();
		derive_key_balloon ((const unsigned char *) PW, pwl, salt, 16, 3, 1024, dk, 192, NULL);
		msB = ms_since (t0);
		get_argon2_params (0, &it, &mc);
		t0 = clock ();
		derive_key_argon2 ((const unsigned char *) PW, pwl, salt, 16, (uint32) it, (uint32) mc, dk, 192, NULL);
		msA = ms_since (t0);
		printf ("BENCH balloon(1MiB,t=3) %.0f ms | argon2id(default m=%d KiB,t=%d) %.0f ms\n",
		        msB, mc, it, msA);
	}

	return 0;
}
