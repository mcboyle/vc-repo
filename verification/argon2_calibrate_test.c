/*
 * argon2_calibrate_test.c — Argon2id auto-calibration to a time budget (ROI item 10) over the REAL
 * Pkcs5.c + Argon2 sources.
 *
 * Verified two ways:
 *   1. the PURE policy Argon2IterationsForBudget is emitted for a grid as 'REF ...' lines and diffed
 *      byte-for-byte against argon2_calibrate_reference.py (independent reimplementation);
 *   2. the REAL integration Argon2CalibrateToTime runs a genuine Argon2id probe over the compiled
 *      Argon2, measures a positive per-iteration cost, and produces iteration counts that are
 *      monotone in the budget and respect the floor/cap — and a back-to-back derive at the larger
 *      budget actually takes longer than at the smaller one (iterations really map to time).
 *
 * Negative control: a broken policy that IGNORES the budget (returns the floor for everything) is run
 * through the same property battery and MUST fail it — proving the properties have teeth.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stddef.h>     /* wchar_t, used by Pkcs5.h declarations */
#include "Common/Pkcs5.h"

/* broken calibration policy for the negative control: ignores targetMs entirely. */
static unsigned int broken_iters_for_budget (unsigned int targetMs, unsigned int perIterMicros,
                                             unsigned int floorIters, unsigned int capIters)
{ (void) targetMs; (void) perIterMicros; (void) capIters; return floorIters; }

/* run the property battery against a policy fn; returns 1 if all properties hold, else 0. */
static int properties_hold (unsigned int (*policy)(unsigned int,unsigned int,unsigned int,unsigned int),
                            unsigned int perIter)
{
	const unsigned int FLOOR = 3, CAP = 1u << 20;
	unsigned int a = policy(40, perIter, FLOOR, CAP);
	unsigned int b = policy(800, perIter, FLOOR, CAP);
	unsigned int tiny = policy(0, perIter, FLOOR, CAP);
	unsigned int huge = policy(1000000000u, perIter, FLOOR, CAP);
	int monotone = (b >= a) && (b > a);          /* a larger budget must buy strictly more iters */
	int floored  = (tiny == FLOOR);              /* a zero budget clamps to the floor */
	int capped   = (huge == CAP);                /* an enormous budget clamps to the cap */
	return monotone && floored && capped;
}

int main (void)
{
	unsigned int per_iter[] = {1, 100, 1000, 5000, 20000, 200000};
	unsigned int target_ms[] = {0, 1, 25, 50, 100, 250, 500, 1000, 5000, 60000};
	unsigned int FLOOR = 3, CAP = 1u << 20;
	int i, j, ok = 1;

	/* (1) emit the pure policy grid for the byte-for-byte python diff */
	for (i = 0; i < (int)(sizeof target_ms/sizeof target_ms[0]); i++)
		for (j = 0; j < (int)(sizeof per_iter/sizeof per_iter[0]); j++)
			printf("REF %u %u %u %u %u\n", target_ms[i], per_iter[j], FLOOR, CAP,
			       Argon2IterationsForBudget(target_ms[i], per_iter[j], FLOOR, CAP));

	/* (2) real integration: probe compiled Argon2, calibrate, check monotone + timed */
	{
		unsigned int perIterMeasured = 0;
		unsigned int itLo, itHi;
		clock_t t0, t1; double tLo, tHi;
		unsigned char pw[8] = "budget!", salt[16] = "budget-salt-000", dk[32];
		unsigned int MEMKIB = 16384;   /* 16 MiB: realistic, keeps the probe fast */

		unsigned int calibrated = Argon2CalibrateToTime(400, MEMKIB, 3, FLOOR, CAP, &perIterMeasured);
		printf("  probe: perIter=%u us, calibrated(400ms)=%u iters\n", perIterMeasured, calibrated);
		if (calibrated == 0 || perIterMeasured == 0) { printf("  REAL: probe failed\n"); ok = 0; }

		itLo = Argon2IterationsForBudget(40,  perIterMeasured, FLOOR, CAP);
		itHi = Argon2IterationsForBudget(800, perIterMeasured, FLOOR, CAP);
		printf("  iters(40ms)=%u  iters(800ms)=%u  (from the same measured perIter)\n", itLo, itHi);
		if (!(itHi > itLo)) { printf("  REAL: iterations not monotone in budget\n"); ok = 0; }
		if (properties_hold(Argon2IterationsForBudget, perIterMeasured))
			printf("  real policy: monotone + floor + cap all hold\n");
		else { printf("  REAL: property battery failed on the real policy\n"); ok = 0; }

		/* back-to-back real derives: the higher iteration count must take longer */
		t0 = clock(); derive_key_argon2(pw, 7, salt, 15, itLo, MEMKIB, dk, 32, NULL); t1 = clock();
		tLo = (double)(t1 - t0) / CLOCKS_PER_SEC;
		t0 = clock(); derive_key_argon2(pw, 7, salt, 15, itHi, MEMKIB, dk, 32, NULL); t1 = clock();
		tHi = (double)(t1 - t0) / CLOCKS_PER_SEC;
		printf("  derive time: %u iters -> %.3fs, %u iters -> %.3fs\n", itLo, tLo, itHi, tHi);
		if (!(tHi > tLo)) { printf("  REAL: more iterations did not cost more time\n"); ok = 0; }
	}

	/* (3) negative control: the broken (budget-ignoring) policy must FAIL the battery */
	{
		int broken_ok = properties_hold(broken_iters_for_budget, 1000);
		if (broken_ok) { printf("  NEGCTL: broken budget-ignoring policy PASSED the battery (no teeth)\n"); ok = 0; }
		else printf("  negctl: broken budget-ignoring policy correctly FAILS the property battery\n");
	}

	printf("%s\n", ok ? "PASS: Argon2 calibration policy matches python + real probe is monotone/timed; negctl fires"
	                   : "FAIL: argon2 calibration");
	return ok ? 0 : 1;
}
