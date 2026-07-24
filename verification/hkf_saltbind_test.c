/*
 * hkf_saltbind_test.c — Rank-1 v2 HKDF salt binding (T2-1 / D-1) over the real
 * HKFMixResponseIntoPasswordV2{,Salt} (gated VC_ENABLE_HKF_MIX_V2_SALTBIND).
 *
 * The v2 HKDF mix (step [80]) extracts with a fixed 0^32 salt. Salt binding folds the VOLUME SALT into
 * HKDF-Extract instead, so the mixed password — and hence the header key — is bound to this volume: a
 * factor response (or reconstructed/threshold secret) enrolled against volume A cannot open volume B at
 * the same password.
 *
 * Verified two ways: the salt-bound mixed password vs an independent python HKDF whose Extract salt IS
 * the volume salt (byte-for-byte, MIXV2SALTEXP), and the UNBOUND path is shown byte-identical to the
 * step-[80] anchor (MIXV2EXP), so enabling the flag does not perturb the plain v2 derivation — it only
 * adds the salt-bound entry point. Properties: different salts -> different keys (cross-volume binding);
 * salt-bound != unbound (binding actually changes the key); a NULL/empty salt falls back to unbound.
 */
#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"

#define POOL HKF_POOL_SIZE   /* 128 */

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-56s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }
static void hexline (const char *t, const unsigned char *b, int n) { int i; printf ("%s ", t); for (i=0;i<n;i++) printf ("%02x", b[i]); printf ("\n"); }

/* mix a copy of (password,pwLen) unbound (0^32 extract salt); write 128 bytes to out. */
static void mix_unbound (const unsigned char *password, int pwLen, const unsigned char *resp, int respLen, unsigned char out[POOL])
{
	unsigned char buf[POOL]; int bl = pwLen;
	memset (buf, 0, sizeof buf); memcpy (buf, password, (size_t) pwLen);
	HKFMixResponseIntoPasswordV2 (buf, &bl, resp, respLen);
	memcpy (out, buf, POOL);
}
/* mix a copy of (password,pwLen) salt-bound (extract salt = salt); write 128 bytes to out. */
static void mix_bound (const unsigned char *password, int pwLen, const unsigned char *resp, int respLen,
                       const unsigned char *salt, int saltLen, unsigned char out[POOL])
{
	unsigned char buf[POOL]; int bl = pwLen;
	memset (buf, 0, sizeof buf); memcpy (buf, password, (size_t) pwLen);
	HKFMixResponseIntoPasswordV2Salt (buf, &bl, resp, respLen, salt, saltLen);
	memcpy (out, buf, POOL);
}

int main (void)
{
	const unsigned char password[] = "hunter2";
	const int pwLen = 7;
	unsigned char resp[32], saltA[64], saltB[64];
	unsigned char unb[POOL], boundA[POOL], boundB[POOL], boundNull[POOL];
	int i;

	for (i = 0; i < 32; i++) resp[i]  = (unsigned char)((i * 11 + 5) & 0xff);
	for (i = 0; i < 64; i++) saltA[i] = (unsigned char)(0xA0 + i);
	for (i = 0; i < 64; i++) saltB[i] = (unsigned char)(0x50 + i);

	mix_unbound (password, pwLen, resp, 32, unb);
	mix_bound   (password, pwLen, resp, 32, saltA, 64, boundA);
	mix_bound   (password, pwLen, resp, 32, saltB, 64, boundB);
	mix_bound   (password, pwLen, resp, 32, 0,     0,  boundNull);

	/* two-way KAT inputs for python (unbound MIXV2EXP + salt-bound MIXV2SALTEXP over SALT=saltA) */
	hexline ("PASSWORD", password, pwLen);
	hexline ("RESPONSE", resp, 32);
	hexline ("SALT", saltA, 64);
	hexline ("MIXV2", unb, POOL);         /* == step-[80] MIXV2EXP: unbound path unchanged */
	hexline ("MIXV2SALT", boundA, POOL);  /* == python MIXV2SALTEXP: salt-bound derivation */

	printf ("[salt binding]\n");
	check ("salt-bound (saltA) differs from unbound (0^32)", memcmp (boundA, unb, POOL) != 0);
	check ("different salts -> different keys (cross-volume binding)", memcmp (boundA, boundB, POOL) != 0);
	check ("NULL/empty salt falls back to the unbound derivation", memcmp (boundNull, unb, POOL) == 0);

	printf ("\n%s\n", all_pass ? "PASS: v2 salt binding — bound differs from unbound, per-salt divergence, null fallback"
	                            : "FAIL: hkf salt binding");
	return all_pass ? 0 : 1;
}
