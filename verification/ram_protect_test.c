/*
 * ram_protect_test.c — the factor secrets are actually ChaCha-protected at rest in RAM.
 *
 * WHAT WAS WRONG
 *
 * KeyScrub's RAM protection (VcKsRamProtect, the Windows VcProtectMemory scheme) was built, proven
 * byte-for-byte against an independent Python reimplementation, and anchored (steps [6] / [98]) — and
 * then called on NOTHING. A grep for its call sites found only VcKsRamProtectInit and
 * VcKsRamProtectShutdown, so HKFConfig.rawSecret / simSecret / fidoPin sat in CLEARTEXT for the whole
 * process lifetime. The primitive was correct; it simply never touched a secret.
 *
 * That is the exact failure recorded at step [106]: an anchor proves a COMPONENT, not that the
 * component is REACHED. A KAT on VcKsRamTransform cannot notice that nobody calls it. This test is the
 * reachability half, and it is deliberately written as an observation of memory rather than as an
 * assertion about control flow — "the plaintext is not there" is the property that matters, and it
 * stays true only if the wiring is real.
 *
 * WHAT THIS PROVES
 *   [1] after HKFSetActiveConfig, the sentinel plaintext is GONE from the config's storage;
 *   [2] HKFComputeResponse still returns the correct response — so the reveal/re-protect pairing is
 *       right, not merely symmetrical-looking (a wrong pairing would corrupt the secret and this
 *       would produce garbage);
 *   [3] after the call returns, the sentinel is gone AGAIN — the window is one call, not the process;
 *   [4] a second call still works, so protection is not a one-shot that silently destroys the secret;
 *   [5] NEGATIVE CONTROL: with the protection area uninitialised, the secret stays in cleartext and
 *       [1] would FAIL. Without this arm the test cannot distinguish "protected" from "the sentinel
 *       search is broken and finds nothing either way".
 *
 * ANCHOR CLASS: PROPERTY / [TWIN-ONLY]. The ChaCha transform underneath is already anchored to
 * libsodium at [98]; what is new here is a liveness property of the fork's own wiring, for which no
 * external vector set exists or could exist.
 */
#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"
#include "Common/KeyScrub.h"

static int pass = 0, fail = 0;
static void ck (const char *what, int ok)
{
	printf ("  %s %s\n", ok ? "ok  " : "FAIL", what);
	if (ok) pass++; else fail++;
}

/* A distinctive 32-byte pattern we can search for. */
static const unsigned char SENTINEL[32] = {
	0x53,0x45,0x4e,0x54,0x49,0x4e,0x45,0x4c, 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
	0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

/* Is the sentinel present verbatim anywhere in the config's secret storage? */
static int sentinel_present (const HKFConfig *cfg)
{
	size_t i;
	for (i = 0; i + sizeof SENTINEL <= sizeof cfg->rawSecret; i++)
		if (memcmp (cfg->rawSecret + i, SENTINEL, sizeof SENTINEL) == 0)
			return 1;
	return 0;
}

static void make_cfg (HKFConfig *cfg)
{
	memset (cfg, 0, sizeof *cfg);
	cfg->backend = HKF_BACKEND_RAW_SECRET;
	memcpy (cfg->rawSecret, SENTINEL, sizeof SENTINEL);
	cfg->rawSecretLen = (int) sizeof SENTINEL;
	/* Raw passthrough, so the expected response IS the secret and [2] is a direct equality test
	   rather than a check against something we would have to recompute. */
	cfg->rawSecretNoBindSalt = 1;
	cfg->rawSecretBindSalt   = 0;
}

int main (void)
{
	HKFConfig cfg;
	unsigned char seed[40], resp[HKF_MAX_RESPONSE], challenge[32];
	int resplen = 0, rc;
	size_t i;

	for (i = 0; i < sizeof seed; i++)      seed[i]      = (unsigned char) (i * 7 + 1);
	for (i = 0; i < sizeof challenge; i++) challenge[i] = (unsigned char) (i + 0xA0);

	printf ("[5] NEGATIVE CONTROL — no protection area: the secret stays in cleartext\n");
	{
		HKFConfig plain;
		VcKsRamProtectShutdown ();            /* ensure the area is NOT initialised */
		make_cfg (&plain);
		HKFSetActiveConfig (&plain);
		ck ("with protection unavailable, the sentinel IS still findable (so the search works)",
		    sentinel_present (&plain));
		HKFSetActiveConfig (0);
	}

	if (!VcKsRamProtectInitFixed (seed))
	{
		printf ("  FAIL could not initialise the RAM-protection area\n");
		return 1;
	}

	make_cfg (&cfg);
	ck ("before adoption the sentinel is present (baseline)", sentinel_present (&cfg));

	printf ("[1] after HKFSetActiveConfig the plaintext is gone\n");
	HKFSetActiveConfig (&cfg);
	ck ("the sentinel is NOT findable in the config's secret storage", !sentinel_present (&cfg));

	printf ("[2] HKFComputeResponse still returns the correct secret\n");
	rc = HKFComputeResponse (&cfg, challenge, (int) sizeof challenge, resp, &resplen);
	ck ("HKFComputeResponse succeeded", rc == HKF_OK);
	ck ("the response equals the original secret (reveal/re-protect pairing is correct)",
	    resplen == (int) sizeof SENTINEL && memcmp (resp, SENTINEL, sizeof SENTINEL) == 0);

	printf ("[3] the secret is protected again once the call returns\n");
	ck ("the sentinel is NOT findable after the response was computed", !sentinel_present (&cfg));

	printf ("[4] protection is not a one-shot — a second call still works\n");
	memset (resp, 0, sizeof resp); resplen = 0;
	rc = HKFComputeResponse (&cfg, challenge, (int) sizeof challenge, resp, &resplen);
	ck ("second HKFComputeResponse also returns the correct secret",
	    rc == HKF_OK && resplen == (int) sizeof SENTINEL &&
	    memcmp (resp, SENTINEL, sizeof SENTINEL) == 0);
	ck ("and the secret is protected again afterwards", !sentinel_present (&cfg));

	HKFSetActiveConfig (0);
	VcKsRamProtectShutdown ();

	printf ("\nRAM-PROTECT: %d passed, %d failed\n", pass, fail);
	return fail ? 1 : 0;
}
