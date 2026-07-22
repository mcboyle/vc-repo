/*
 * log_redaction_test.c — mechanical log-redaction check (ROI-TOP-50 item 14).
 *
 * Secrets must never reach a log, diagnostic dump, or verbose summary — and that has to be proven by
 * grepping output, not by code review. This harness loads DISTINCTIVE sentinel secrets into an
 * HKFConfig (the reconstructed factor secret, the simulator secret, and the FIDO2 PIN) and a password
 * buffer, drives the real integration path (HKFApplyIfConfigured mixes the factor into the password),
 * then emits the kind of "verbose config summary" a --verbose/debug mode would print. build_and_verify
 * greps ALL of this program's output for the sentinels: a clean build must contain NONE of them.
 *
 * VC_LOGLEAK compiles the deliberately-leaky variant (the summary dumps the PIN and the raw secret
 * bytes). The grep MUST find the sentinels there — that is the negative control proving the check has
 * teeth (a real redaction regression would look exactly like the leaky build).
 *
 * The sentinels are chosen so a partial/encoded leak is still caught: the ASCII marker, and the raw
 * secret's hex, are both grepped for.
 */
#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"

/* Distinctive, unlikely-to-collide sentinels (also referenced verbatim by build_and_verify.sh). */
#define PIN_SENTINEL    "REDACT_SENTINEL_PIN_7c1f9a2b"
#define RAW_SENTINEL    "REDACT_SENTINEL_RAW_4e8d1c60"   /* placed as bytes in rawSecret */
#define PW_SENTINEL     "REDACT_SENTINEL_PW_a19f33d7"

static void print_hex (const char *label, const unsigned char *p, int n)
{
	int i;
	printf ("%s", label);
	for (i = 0; i < n; i++) printf ("%02x", p[i]);
	printf ("\n");
}

int main (void)
{
	HKFConfig cfg;
	unsigned char password[128];
	int pwLen;
	unsigned char salt[64];
	int i;

	memset (&cfg, 0, sizeof (cfg));
	cfg.backend = HKF_BACKEND_RAW_SECRET;

	/* load sentinel secrets */
	memcpy (cfg.rawSecret, RAW_SENTINEL, sizeof (RAW_SENTINEL) - 1);
	cfg.rawSecretLen = (int) (sizeof (RAW_SENTINEL) - 1);
	memcpy (cfg.simSecret, RAW_SENTINEL, sizeof (RAW_SENTINEL) - 1);
	cfg.simSecretLen = (int) (sizeof (RAW_SENTINEL) - 1);
	strcpy (cfg.fidoPin, PIN_SENTINEL);
	strcpy (cfg.fidoRpId, "veracrypt-volume");     /* public metadata, deliberately NOT a sentinel */

	memcpy (password, PW_SENTINEL, sizeof (PW_SENTINEL) - 1);
	pwLen = (int) (sizeof (PW_SENTINEL) - 1);
	for (i = 0; i < (int) sizeof (salt); i++) salt[i] = (unsigned char) (i * 3 + 1);

	/* Drive the real integration path: mix the factor secret into the password. The mixed password is
	 * secret-derived and must never be printed either — we deliberately do NOT print it here. */
	HKFSetActiveConfig (&cfg);
	(void) HKFApplyIfConfigured (password, &pwLen, salt, (int) sizeof (salt));

	/* --- the diagnostic surface a --verbose mode would emit: SAFE metadata only --- */
	printf ("HKF config summary:\n");
	printf ("  backend            = RAW_SECRET\n");
	printf ("  fido rp id         = %s\n", cfg.fidoRpId);           /* public, fine */
	printf ("  yubikey slot       = %d\n", cfg.ykSlot);
	printf ("  raw secret length  = %d bytes\n", cfg.rawSecretLen); /* length, not content */
	printf ("  fido pin           = %s\n", cfg.fidoPin[0] ? "[set, redacted]" : "[none]");
	printf ("  factor applied     = yes\n");

#if defined(VC_LOGLEAK)
	/* NEGATIVE CONTROL: a redaction regression — the summary dumps real secret material. */
	printf ("  fido pin (LEAK)    = %s\n", cfg.fidoPin);
	print_hex ("  raw secret (LEAK)  = ", cfg.rawSecret, cfg.rawSecretLen);
#endif

	HKFScrubActiveConfig ();
	return 0;
}
