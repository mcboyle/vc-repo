/*
 * saltbind_test.c — verification for RAW_SECRET salt-binding.
 *
 * Drives the REAL Common/HardwareKeyFactor.c HKFComputeResponse with a RAW_SECRET config whose
 * rawSecretBindSalt flag is set: the response must be HMAC-SHA256(secret, salt) computed over the real
 * in-tree Sha2.c (layer 2). saltbind_reference.py is the independent HMAC-SHA256 (layer 1); the "REF"
 * line is diffed byte-for-byte. Also checks that with the flag off the raw secret is returned unchanged.
 */

#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"

static void hex (const char *l, const unsigned char *p, int n)
{ int i; printf ("%s", l); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

#define SECRET_LEN 32
#define SALT_LEN   64

int main (void)
{
	HKFConfig cfg;
	unsigned char salt[SALT_LEN], resp[HKF_MAX_RESPONSE];
	int rlen = 0, i, rc;

	memset (&cfg, 0, sizeof (cfg));
	cfg.backend = HKF_BACKEND_RAW_SECRET;
	for (i = 0; i < SECRET_LEN; i++) cfg.rawSecret[i] = (unsigned char) (0x50 + i);
	cfg.rawSecretLen = SECRET_LEN;
	for (i = 0; i < SALT_LEN; i++) salt[i] = (unsigned char) ((i * 3 + 7) & 0xff);

	/* salt-bound: response = HMAC-SHA256(secret, salt) */
	cfg.rawSecretBindSalt = 1;
	rc = HKFComputeResponse (&cfg, salt, SALT_LEN, resp, &rlen);
	printf ("[A] compute rc ok: %s\n", rc == HKF_OK ? "YES" : "NO");
	printf ("[A] response length == 32: %s\n", rlen == 32 ? "YES" : "NO");
	hex ("REF saltbound = ", resp, 32);

	/* unbound: response == raw secret unchanged */
	cfg.rawSecretBindSalt = 0;
	memset (resp, 0, sizeof (resp)); rlen = 0;
	rc = HKFComputeResponse (&cfg, salt, SALT_LEN, resp, &rlen);
	{
		int same = (rc == HKF_OK) && rlen == SECRET_LEN && memcmp (resp, cfg.rawSecret, SECRET_LEN) == 0;
		printf ("[B] unbound returns raw secret unchanged: %s\n", same ? "YES" : "NO");
	}

	/* salt-binding actually depends on the salt: a different salt -> different response */
	{
		unsigned char salt2[SALT_LEN], r1[HKF_MAX_RESPONSE], r2[HKF_MAX_RESPONSE];
		int l1 = 0, l2 = 0;
		cfg.rawSecretBindSalt = 1;
		HKFComputeResponse (&cfg, salt, SALT_LEN, r1, &l1);
		memcpy (salt2, salt, SALT_LEN); salt2[0] ^= 0x01;
		HKFComputeResponse (&cfg, salt2, SALT_LEN, r2, &l2);
		printf ("[C] different salt -> different response: %s\n", memcmp (r1, r2, 32) != 0 ? "YES" : "NO");
	}

	return 0;
}
