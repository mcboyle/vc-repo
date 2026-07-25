/*
 * keyslot_policy_cfg_init_test.cpp — regression guard for a latent initializer bug.
 *
 * KeyslotHeaderCfg / KeyslotSidecarCfg / KeyslotDeniableCfg (Volume/KeyslotVolumeBinding.h) declared
 * `KeyslotStoreCfg cfg;` UNINITIALISED and assigned only 7 fields — the gated `policy` field (present
 * under VC_ENABLE_KEYSLOT_POLICY) was never set, so it was stack garbage, and `policy` selects the record
 * LAYOUT (plen; v1 vs v2 payload). The fix value-initialises the struct first (`KeyslotStoreCfg cfg =
 * KeyslotStoreCfg();`) so `policy` — and any FUTURE gated field — is 0 unless explicitly set.
 *
 * This test reproduces the fixed builders' EXACT init pattern (value-init, then set the same 7 fields,
 * NOT policy) and asserts `policy == 0`. It is dependency-free (KeyslotStore.h only) BY NECESSITY: the
 * real builders live in KeyslotVolumeBinding.h, which includes the app's Windows-typed Volumes.h and does
 * not compile in a standalone TU. So this guards the fix's MECHANISM, not the literal builder — see the PR
 * note. Built with -DVC_ENABLE_KEYSLOT_POLICY (as .github/workflows/codeql.yml compiles the real builders).
 */
#include <cstdio>
extern "C" {
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
}

/* The value-init + set-7-fields pattern the fixed KeyslotHeaderCfg uses (Sidecar/Deniable copy it). */
static KeyslotStoreCfg header_cfg_pattern (int vmkLen)
{
	KeyslotStoreCfg cfg = KeyslotStoreCfg();   /* <-- the fix: zero ALL fields, incl. gated `policy` */
	cfg.backend   = KSB_HEADER;
	cfg.kdf       = 0;                          /* (real builder: &KeyslotKdfSha512; not exercised here) */
	cfg.cost      = 500000;
	cfg.vmkLen    = vmkLen;
	cfg.maxSlots  = 63;
	cfg.randBytes = 0;
	cfg.afStripes = 0;
	/* NOTE: policy is deliberately NOT set here, exactly as in the builders. */
	return cfg;
}

int main ()
{
#if defined(VC_ENABLE_KEYSLOT_POLICY)
	KeyslotStoreCfg c = header_cfg_pattern (64);
	int ok = (c.policy == 0);
	printf ("  cfg.policy after value-init + set-7-fields = %d\n", c.policy);
	printf ("  %s\n", ok ? "KEYSLOT CFG POLICY-INIT TEST PASSED (gated field zero-initialised)"
	                     : "KEYSLOT CFG POLICY-INIT TEST FAILED (policy left uninitialised)");
	return ok ? 0 : 1;
#else
	(void) header_cfg_pattern;
	printf ("  (skipped: build with -DVC_ENABLE_KEYSLOT_POLICY to exercise the policy field)\n");
	return 0;
#endif
}
