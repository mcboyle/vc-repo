/*
 * VcStatus — structured error taxonomy + STABLE process exit codes (ROI-TOP-50 item 47).
 *
 * Scripts need to branch on *why* an operation failed without scraping human text. This defines a
 * stable enum of outcomes for the fork's operations (mount/keyslot/factor), each with a fixed process
 * exit code, a stable machine-readable name (for --json, item 48), and a human string. The exit-code
 * and name mappings are a committed contract: a stability KAT in verification/ fails if any value is
 * renumbered, so downstream scripts can rely on them. Gated behind VC_ENABLE_STATUS.
 */
#ifndef TC_HEADER_Common_VcStatus
#define TC_HEADER_Common_VcStatus

#include "Tcdefs.h"

#if defined(VC_ENABLE_STATUS)

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum
{
	VC_OK                 = 0,   /* success                                                     */
	VC_ERR_PARAM          = 1,   /* bad argument / usage                                        */
	VC_ERR_IO             = 2,   /* read/write/open failure on the volume or a file             */
	VC_ERR_WRONG_PASSWORD = 3,   /* no keyslot / header opened with the given passphrase         */
	VC_ERR_FACTOR_MISSING = 4,   /* a required hardware/threshold factor was absent              */
	VC_ERR_SLOT_EXPIRED   = 5,   /* the matched keyslot is past its expiry (policy)             */
	VC_ERR_SLOT_LOCKED    = 6,   /* the keyslot is locked out (max-attempts, policy)            */
	VC_ERR_DURESS         = 7,   /* a duress passphrase/slot was used (safe action taken)       */
	VC_ERR_TAMPERED       = 8,   /* an authentication tag / integrity check failed              */
	VC_ERR_UNSUPPORTED    = 9,   /* the operation is not supported in this build/backend        */
	VC_ERR_INTERNAL       = 10,  /* an unexpected internal error                                */
	VC_STATUS_COUNT       = 11   /* number of defined statuses (keep last)                       */
} VcStatus;

/* Stable process exit code for a status (0 == success). Distinct, small, documented, and pinned by a
   verification KAT — do not renumber without updating docs and downstream scripts. */
int         VcStatusExitCode (VcStatus s);
/* Stable machine-readable token, e.g. "wrong_password" (for --json / scripting). Never NULL. */
const char *VcStatusName     (VcStatus s);
/* Human-readable one-line description. Never NULL. */
const char *VcStatusString   (VcStatus s);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_STATUS */

#endif /* TC_HEADER_Common_VcStatus */
