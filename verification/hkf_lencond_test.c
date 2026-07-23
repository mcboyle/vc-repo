/*
 * hkf_lencond_test.c — HKF response length conditioning (CRC-seam addendum §6) over the real
 * HKFComputeResponse.
 *
 * Compiled TWICE by the suite: once WITH -DVC_ENABLE_HKF_LEN_CONDITION (cond) and once without
 * (nocond). It prints, for a set of RAW_SECRET lengths, the actual response length + bytes returned
 * by the real HKFComputeResponse, plus the pool write-schedule max (the §2 wrap boundary, a pure
 * combinatorial check independent of the flag).
 *
 * The suite then checks:
 *   - cond: every response is <= 32 bytes; a >32-byte secret becomes sha256(secret) (matched
 *     byte-for-byte against hkf_lencond_reference.py); a <=32-byte secret is unchanged (no-op).
 *   - nocond (NEGATIVE CONTROL): a 64-byte secret stays 64 bytes — the reachable gap the fix closes;
 *     and the §2 counter shows that 64-byte input wraps the pool (max writes 2) while the conditioned
 *     32-byte length does not (max writes 1).
 */
#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"

static const int LENS[] = { 20, 32, 33, 48, 64 };
#define NLEN (int)(sizeof(LENS)/sizeof(LENS[0]))
#define POOL 128

/* replicate the pool write schedule (4 pool bytes per input byte, wrap at 128); return max writes. */
static int max_writes (int L)
{
	int counts[POOL], wp = 0, i, j, m = 0;
	memset (counts, 0, sizeof counts);
	for (i = 0; i < L; i++)
		for (j = 0; j < 4; j++) { counts[wp]++; if (++wp >= POOL) wp = 0; }
	for (i = 0; i < POOL; i++) if (counts[i] > m) m = counts[i];
	return m;
}

int main (void)
{
	unsigned char challenge[32];
	int i, k;
	memset (challenge, 0xAB, sizeof challenge);

#if defined(VC_ENABLE_HKF_LEN_CONDITION)
	printf ("MODE cond\n");
#else
	printf ("MODE nocond\n");
#endif
	for (i = 0; i < NLEN; i++) {
		HKFConfig c; unsigned char resp[HKF_MAX_RESPONSE]; int outlen = -1, rc;
		int L = LENS[i];
		memset (&c, 0, sizeof c);
		c.backend = HKF_BACKEND_RAW_SECRET;
		c.rawSecretLen = L;
		for (k = 0; k < L; k++) c.rawSecret[k] = (unsigned char)((k * 7 + 1) & 0xff);
		rc = HKFComputeResponse (&c, challenge, sizeof challenge, resp, &outlen);
		if (rc != 0) { printf ("RESP %d ERR\n", L); continue; }
		printf ("RESP %d %d ", L, outlen);
		for (k = 0; k < outlen; k++) printf ("%02x", resp[k]);
		printf ("\n");
		printf ("WRAP %d %d\n", L, max_writes (L));
	}
	printf ("WRAP 32 %d\n", max_writes (32));
	return 0;
}
