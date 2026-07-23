/*
 * hkf_saltdefault_test.c — salt-binding on by default (addendum Rec 1) over the real
 * HKFApplySaltBindDefault + HKFComputeResponse.
 *
 * Compiled TWICE by the suite:
 *   - DEFAULT build: -DVC_ENABLE_HKF -DVC_ENABLE_HKF_SALT_BIND -DVC_ENABLE_HKF_SALT_BIND_DEFAULT
 *   - LEGACY  build: -DVC_ENABLE_HKF -DVC_ENABLE_HKF_SALT_BIND        (default-on flag absent)
 *
 * For a RAW_SECRET factor it applies HKFApplySaltBindDefault() then computes the response:
 *   config A (no opt-out):  default build -> salt-bound, 32-byte HMAC-SHA256(secret, salt)
 *                           legacy  build -> raw, 64 bytes  (default NOT applied — the gap Rec 1 closes)
 *   config B (opt-out set): both builds    -> raw, 64 bytes (--hkf-no-bind-salt preserves legacy)
 *
 * The suite diffs the default build's config-A response byte-for-byte against
 * hkf_saltdefault_reference.py (HMAC-SHA256(secret, salt)), and asserts the LEGACY build leaves the
 * factor unbound (negative control).
 */
#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"

static unsigned char g_secret[64], g_salt[64];

static void run (char tag, int optOut)
{
	HKFConfig c; unsigned char resp[HKF_MAX_RESPONSE]; int outlen = -1, rc, k;
	memset (&c, 0, sizeof c);
	c.backend = HKF_BACKEND_RAW_SECRET;
	c.rawSecretLen = 64;
	memcpy (c.rawSecret, g_secret, 64);
	c.rawSecretNoBindSalt = optOut;
	HKFApplySaltBindDefault (&c);                       /* Rec 1 policy */
	rc = HKFComputeResponse (&c, g_salt, 64, resp, &outlen);   /* challenge = the volume salt */
	printf ("%c bind=%d rc=%d outlen=%d ", tag, c.rawSecretBindSalt, rc, outlen);
	for (k = 0; k < (outlen > 0 ? outlen : 0); k++) printf ("%02x", resp[k]);
	printf ("\n");
}

int main (void)
{
	int i, ok = 1, aBind, aLen, bBind, bLen;
	char line[8]; (void) line;
	for (i = 0; i < 64; i++) g_secret[i] = (unsigned char)((i * 5 + 3) & 0xff);
	for (i = 0; i < 64; i++) g_salt[i]   = (unsigned char)(0xA0 ^ i);

#if defined(VC_ENABLE_HKF_SALT_BIND_DEFAULT)
	printf ("MODE default\n");
#else
	printf ("MODE legacy\n");
#endif
	run ('A', 0);   /* no opt-out */
	run ('B', 1);   /* --hkf-no-bind-salt */
	printf ("SECRET "); for (i = 0; i < 64; i++) printf ("%02x", g_secret[i]); printf ("\n");
	printf ("SALT ");   for (i = 0; i < 64; i++) printf ("%02x", g_salt[i]);   printf ("\n");

	/* mode-internal invariants (recompute locally to self-check) */
	{
		HKFConfig a, b; unsigned char r[HKF_MAX_RESPONSE]; int la = -1, lb = -1;
		memset (&a, 0, sizeof a); a.backend = HKF_BACKEND_RAW_SECRET; a.rawSecretLen = 64; memcpy (a.rawSecret, g_secret, 64);
		memset (&b, 0, sizeof b); b.backend = HKF_BACKEND_RAW_SECRET; b.rawSecretLen = 64; memcpy (b.rawSecret, g_secret, 64); b.rawSecretNoBindSalt = 1;
		HKFApplySaltBindDefault (&a); HKFApplySaltBindDefault (&b);
		aBind = a.rawSecretBindSalt; HKFComputeResponse (&a, g_salt, 64, r, &la); aLen = la;
		bBind = b.rawSecretBindSalt; HKFComputeResponse (&b, g_salt, 64, r, &lb); bLen = lb;
	}
#if defined(VC_ENABLE_HKF_SALT_BIND_DEFAULT)
	if (!(aBind == 1 && aLen == 32)) { printf ("  FAIL: default did not salt-bind config A\n"); ok = 0; }
	if (!(bBind == 0 && bLen == 64)) { printf ("  FAIL: opt-out did not preserve legacy for config B\n"); ok = 0; }
	if (ok) printf ("  default: A salt-bound (32B), B opt-out raw (64B)\n");
#else
	if (!(aBind == 0 && aLen == 64)) { printf ("  FAIL: legacy build unexpectedly salt-bound\n"); ok = 0; }
	if (ok) printf ("  legacy: A raw (64B) — default not applied (the gap Rec 1 closes)\n");
#endif
	printf ("%s\n", ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}
