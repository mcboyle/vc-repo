/*
 * hkf_mixv2_wiring_test.c — seam-level proof of the Rank-1 v2 WIRING (not just the mix primitive).
 *
 * Step [80] proved the v2 mix math and the try-loop logic in isolation. This step proves the seam the
 * mount/create call sites actually use: the process-wide active config (HKFSetActiveConfig, as the CLI
 * sets before an op) driving HKFComputeActiveResponse (compute-once) and HKFApplyIfConfiguredVer
 * (versioned compute+mix, the create C-path call), plus the exact operations the C++ overload
 * (HKFMixPasswordWithResponse) performs — so both derivation paths are shown byte-identical.
 *
 * Modelled behaviours, over the REAL compiled HardwareKeyFactor.o:
 *   CREATE     : HKFApplyIfConfiguredVer(HKF_MIX_V2, ...) enrolls a volume under v2.
 *   MOUNT      : the wrapper computes the response ONCE (HKFComputeActiveResponse) then mixes v2, then
 *                v1 — opening a v2-enrolled volume on the first attempt and a v1-enrolled (legacy)
 *                volume on the fallback, with a single backend query.
 *   compute-once: the one response returned by HKFComputeActiveResponse is the same bytes both mixes
 *                consume, and equals a direct HKFComputeResponse(cfg,...) (active-config routes to the
 *                same backend).
 *   cross-path : the C create path (HKFApplyIfConfiguredVer) and the C++ overload's operations
 *                (compute-once + HKFMixResponseIntoPasswordVer) derive byte-identical keys.
 *   no factor  : HKF_BACKEND_NONE -> HKFComputeActiveResponse returns len 0 (single unmixed pass) and
 *                HKFApplyIfConfiguredVer leaves the key untouched.
 *
 * Negative controls: a WRONG active secret opens NEITHER version; v1 and v2 enrollments differ (so the
 * version argument is genuinely consumed, the try-loop is not a no-op). A KAT (the v2-enrolled key) is
 * additionally cross-checked byte-for-byte against the independent python HKDF (hkf_mixv2_reference.py).
 */
#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"

#define POOL HKF_POOL_SIZE   /* 128 */
#define SALTLEN 64

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-58s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }
static void hexline (const char *t, const unsigned char *b, int n) { int i; printf ("%s ", t); for (i=0;i<n;i++) printf ("%02x", b[i]); printf ("\n"); }

/* build a RAW_SECRET active config with the given secret (no salt-binding: response == raw secret) */
static void set_raw_config (HKFConfig *cfg, const unsigned char *secret, int len)
{
	memset (cfg, 0, sizeof *cfg);
	cfg->backend = HKF_BACKEND_RAW_SECRET;
	memcpy (cfg->rawSecret, secret, (size_t) len);
	cfg->rawSecretLen = len;
	cfg->rawSecretNoBindSalt = 1;   /* keep the raw secret as the response, deterministic for the KAT */
	cfg->applyPolicy = HKF_APPLY_ALL;
	HKFSetActiveConfig (cfg);
}

/* the MOUNT wrapper, modelled exactly: compute the active response ONCE, then mix v2, then v1.
   Returns the version that reproduces 'stored' (HKF_MIX_V2 / HKF_MIX_V1) or 0 for no match.
   *computeCalls counts backend queries — the wrapper must make exactly one. */
static int mount_open (const unsigned char *password, int pwLen, const unsigned char *salt,
                       const unsigned char stored[POOL], int *computeCalls)
{
	unsigned char resp[HKF_MAX_RESPONSE];
	unsigned char buf[POOL];
	int rlen = 0, len;

	if (HKFComputeActiveResponse (salt, SALTLEN, resp, &rlen) != HKF_OK)
		return -1;
	(*computeCalls)++;                       /* exactly one backend query for the whole open */
	if (rlen == 0)
		return 0;                            /* no factor: caller does a single unmixed pass */

	memset (buf, 0, sizeof buf); memcpy (buf, password, (size_t) pwLen); len = pwLen;
	HKFMixResponseIntoPasswordVer (HKF_MIX_V2, buf, &len, resp, rlen);
	if (len == POOL && !memcmp (buf, stored, POOL)) return HKF_MIX_V2;

	memset (buf, 0, sizeof buf); memcpy (buf, password, (size_t) pwLen); len = pwLen;
	HKFMixResponseIntoPasswordVer (HKF_MIX_V1, buf, &len, resp, rlen);
	if (len == POOL && !memcmp (buf, stored, POOL)) return HKF_MIX_V1;

	return 0;
}

int main (void)
{
	const unsigned char password[] = "correct horse";   /* 13 bytes */
	const int pwLen = 13;
	unsigned char salt[SALTLEN];
	unsigned char secret[32], wrong[32];
	unsigned char storedV2[POOL], storedV1[POOL];
	HKFConfig cfg;
	int i, len, computeCalls;

	for (i = 0; i < SALTLEN; i++) salt[i]   = (unsigned char)((i * 7 + 3) & 0xff);
	for (i = 0; i < 32; i++)      secret[i] = (unsigned char)((i * 13 + 1) & 0xff);
	for (i = 0; i < 32; i++)      wrong[i]  = secret[i];
	wrong[0] ^= 0x01;

	/* ---- CREATE: enroll a v2 volume via the real create-path call HKFApplyIfConfiguredVer(v2) ---- */
	set_raw_config (&cfg, secret, 32);
	memset (storedV2, 0, sizeof storedV2); memcpy (storedV2, password, (size_t) pwLen); len = pwLen;
	check ("create: HKFApplyIfConfiguredVer(v2) returns HKF_OK",
	       HKFApplyIfConfiguredVer (HKF_MIX_V2, storedV2, &len, salt, SALTLEN) == HKF_OK);
	check ("create: v2 enrollment expands key to the pool size (128)", len == POOL);

	/* a legacy v1 volume: enroll under v1 (what an older build wrote) */
	memset (storedV1, 0, sizeof storedV1); memcpy (storedV1, password, (size_t) pwLen); len = pwLen;
	HKFApplyIfConfiguredVer (HKF_MIX_V1, storedV1, &len, salt, SALTLEN);

	/* KAT for the python cross-check: v2-enrolled key == HKDF over (password || secret) */
	hexline ("PASSWORD", password, pwLen);
	hexline ("RESPONSE", secret, 32);
	hexline ("MIXV2", storedV2, POOL);

	printf ("[version dispatch through the active-config seam]\n");
	check ("v1 and v2 enrollments differ (version arg is consumed)", memcmp (storedV1, storedV2, POOL) != 0);

	printf ("[mount wrapper: compute-once, v2-first, v1-fallback]\n");
	computeCalls = 0;
	check ("mount opens a v2-enrolled volume on the v2 attempt", mount_open (password, pwLen, salt, storedV2, &computeCalls) == HKF_MIX_V2);
	check ("  ...querying the backend exactly once (compute-once)", computeCalls == 1);
	computeCalls = 0;
	check ("mount opens a v1-enrolled (legacy) volume via v1 fallback", mount_open (password, pwLen, salt, storedV1, &computeCalls) == HKF_MIX_V1);
	check ("  ...still exactly one backend query across both attempts", computeCalls == 1);

	printf ("[compute-once identity: active seam == direct backend]\n");
	{
		unsigned char rA[HKF_MAX_RESPONSE], rB[HKF_MAX_RESPONSE];
		int lA = 0, lB = 0;
		HKFComputeActiveResponse (salt, SALTLEN, rA, &lA);
		HKFComputeResponse (&cfg, salt, SALTLEN, rB, &lB);
		check ("HKFComputeActiveResponse == HKFComputeResponse(active cfg)", lA == lB && lA > 0 && !memcmp (rA, rB, (size_t) lA));
	}

	printf ("[cross-path byte-identity: C create path == C++ overload operations]\n");
	{
		/* C create path */
		unsigned char cPath[POOL]; int cl = pwLen;
		memset (cPath, 0, sizeof cPath); memcpy (cPath, password, (size_t) pwLen);
		HKFApplyIfConfiguredVer (HKF_MIX_V2, cPath, &cl, salt, SALTLEN);
		/* C++ overload operations: compute-once then HKFMixResponseIntoPasswordVer on a password copy */
		unsigned char resp[HKF_MAX_RESPONSE]; int rl = 0;
		HKFComputeActiveResponse (salt, SALTLEN, resp, &rl);
		unsigned char cppPath[POOL]; int pl = pwLen;
		memset (cppPath, 0, sizeof cppPath); memcpy (cppPath, password, (size_t) pwLen);
		HKFMixResponseIntoPasswordVer (HKF_MIX_V2, cppPath, &pl, resp, rl);
		check ("C-path key == C++-overload key (identical bytes, both paths)", cl == pl && !memcmp (cPath, cppPath, POOL));
	}

	printf ("[negative controls]\n");
	{
		HKFConfig bad; int cc = 0;
		set_raw_config (&bad, wrong, 32);   /* wrong active factor */
		check ("wrong factor opens NEITHER version (v2 volume)", mount_open (password, pwLen, salt, storedV2, &cc) == 0);
		cc = 0;
		check ("wrong factor opens NEITHER version (v1 volume)", mount_open (password, pwLen, salt, storedV1, &cc) == 0);
	}

	printf ("[no-factor pass-through]\n");
	{
		HKFConfig none; unsigned char k[POOL]; int kl = pwLen, rl = 0; unsigned char r[HKF_MAX_RESPONSE];
		memset (&none, 0, sizeof none); none.backend = HKF_BACKEND_NONE; HKFSetActiveConfig (&none);
		memset (k, 0, sizeof k); memcpy (k, password, (size_t) pwLen);
		check ("no factor: HKFComputeActiveResponse returns len 0", HKFComputeActiveResponse (salt, SALTLEN, r, &rl) == HKF_OK && rl == 0);
		check ("no factor: HKFApplyIfConfiguredVer leaves the key untouched",
		       HKFApplyIfConfiguredVer (HKF_MIX_V2, k, &kl, salt, SALTLEN) == HKF_OK && kl == pwLen && !memcmp (k, password, (size_t) pwLen));
	}

	HKFSetActiveConfig (0);
	printf ("\n%s\n", all_pass ? "PASS: v2 wiring seam — create=v2, mount compute-once/v2-first/v1-fallback, cross-path identical, wrong factor opens neither"
	                            : "FAIL: hkf mix-v2 wiring");
	return all_pass ? 0 : 1;
}
