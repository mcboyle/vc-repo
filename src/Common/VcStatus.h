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

/* ---------------------------------------------------------------------------------------------
   MOUNT-PATH PARTITION — the anti-coercion-oracle mapping.

   The table above is deliberately fine-grained: an administrator running --keyslot-list or a
   recovery tool wants to know EXACTLY why something failed. On the MOUNT path that same precision
   is a coercion oracle. An adversary holding the decoy passphrase who can see distinct outcomes for
   "wrong password" (77), "factor missing" (69), "slot expired" (75), "slot locked" (76) and
   "duress" (78) learns that a hardware/threshold factor is configured, that keyslot policies exist,
   and -- worst -- that a duress passphrase was recognised. Two shipped specs already require the
   opposite: KEYSLOT-POLICY-DESIGN.md mandates SILENT expiry, and DURESS-DISMOUNT-SPEC.md mandates
   that a duress passphrase be indistinguishable from an ordinary failure.

   VcStatusMountSafe collapses exactly the CREDENTIAL-DEPENDENT outcomes into one class. Membership
   is decided by a single question: "can an adversary learn this by trying passphrases?"

     COLLAPSED (credential-dependent -> VC_ERR_WRONG_PASSWORD):
       VC_ERR_WRONG_PASSWORD, VC_ERR_FACTOR_MISSING, VC_ERR_SLOT_EXPIRED,
       VC_ERR_SLOT_LOCKED, VC_ERR_DURESS
     NOT COLLAPSED (independent of which credential was supplied):
       VC_OK           -- success is observable anyway
       VC_ERR_PARAM    -- bad usage; the user typed the command, no secret involved
       VC_ERR_IO       -- the file is missing/unreadable; visible without any passphrase
       VC_ERR_UNSUPPORTED -- a build-configuration fact, identical for every passphrase
       VC_ERR_INTERNAL -- a bug; suppressing it would hide faults without hiding secrets
       VC_ERR_TAMPERED -- a DIFFERENT axis. Tamper detection is a feature this fork deliberately
                          surfaces (v2 fail-closed reads, --list -v). It reports that the MEDIUM was
                          modified, which an adversary who modified it already knows, and it is not
                          learned by guessing passphrases. Collapsing it would silently undo shipped
                          tamper-evidence to buy nothing.

   COLLAPSING DURESS DOES NOT DISABLE THE DURESS ACTION. The dismount-all-and-scrub path still runs
   exactly as before; only the OUTCOME REPORTED to the caller becomes generic. That is the whole
   point -- the action must be invisible, not absent.

   Callers on the mount path must route every status through this before it reaches an exit code, a
   --json field, or a message. Fine-grained codes remain correct for admin/recovery paths.
   --------------------------------------------------------------------------------------------- */
VcStatus    VcStatusMountSafe (VcStatus s);
/* 1 if s is credential-dependent and therefore collapsed by VcStatusMountSafe; 0 otherwise.
   Exposed so tests can assert the partition directly rather than re-deriving the membership list. */
int         VcStatusIsCredentialDependent (VcStatus s);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_STATUS */

#endif /* TC_HEADER_Common_VcStatus */
