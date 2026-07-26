/*
 * VcStatus — see VcStatus.h. Stable exit-code / name / string tables.
 */
#include "VcStatus.h"

#if defined(VC_ENABLE_STATUS)

typedef struct { int exitCode; const char *name; const char *desc; } VcStatusEntry;

/* Indexed by VcStatus. The exit codes are a committed contract (pinned by verification/status_test.c);
   keep them distinct and do not renumber. */
static const VcStatusEntry TABLE[VC_STATUS_COUNT] = {
	/* VC_OK                 */ { 0,  "ok",                 "success" },
	/* VC_ERR_PARAM          */ { 64, "param",              "invalid argument or usage" },
	/* VC_ERR_IO             */ { 74, "io",                 "read/write/open failure" },
	/* VC_ERR_WRONG_PASSWORD */ { 77, "wrong_password",     "no keyslot or header opened with the given passphrase" },
	/* VC_ERR_FACTOR_MISSING */ { 69, "factor_missing",     "a required hardware/threshold factor was absent" },
	/* VC_ERR_SLOT_EXPIRED   */ { 75, "slot_expired",       "the matched keyslot is past its expiry" },
	/* VC_ERR_SLOT_LOCKED    */ { 76, "slot_locked",        "the keyslot is locked out (max attempts reached)" },
	/* VC_ERR_DURESS         */ { 78, "duress",             "a duress passphrase was used; safe action taken" },
	/* VC_ERR_TAMPERED       */ { 79, "tampered",           "an authentication tag or integrity check failed" },
	/* VC_ERR_UNSUPPORTED    */ { 70, "unsupported",        "the operation is not supported in this build" },
	/* VC_ERR_INTERNAL       */ { 71, "internal",           "an unexpected internal error occurred" }
};

static int in_range (VcStatus s) { return (int) s >= 0 && (int) s < VC_STATUS_COUNT; }

int VcStatusExitCode (VcStatus s)      { return in_range (s) ? TABLE[s].exitCode : TABLE[VC_ERR_INTERNAL].exitCode; }
const char *VcStatusName (VcStatus s)  { return in_range (s) ? TABLE[s].name     : TABLE[VC_ERR_INTERNAL].name; }
const char *VcStatusString (VcStatus s){ return in_range (s) ? TABLE[s].desc     : TABLE[VC_ERR_INTERNAL].desc; }

int VcStatusIsCredentialDependent (VcStatus s)
{
	switch (s)
	{
	case VC_ERR_WRONG_PASSWORD:
	case VC_ERR_FACTOR_MISSING:
	case VC_ERR_SLOT_EXPIRED:
	case VC_ERR_SLOT_LOCKED:
	case VC_ERR_DURESS:
		return 1;
	default:
		return 0;
	}
}

VcStatus VcStatusMountSafe (VcStatus s)
{
	/* Everything an adversary could learn by trying passphrases becomes one indistinguishable
	   answer. VC_ERR_WRONG_PASSWORD is the collapse target because it is what stock VeraCrypt already
	   says for a failed mount, so the fork's mount path stays indistinguishable from upstream's. */
	if (VcStatusIsCredentialDependent (s))
		return VC_ERR_WRONG_PASSWORD;
	return in_range (s) ? s : VC_ERR_INTERNAL;
}

#endif /* VC_ENABLE_STATUS */
