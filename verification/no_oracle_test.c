/*
 * no_oracle_test.c — the mount path must not be a coercion oracle.
 *
 * THE DEFECT THIS PINS
 *
 * VcStatus hands out distinct, stable, documented exit codes: wrong_password (77), factor_missing
 * (69), slot_expired (75), slot_locked (76), duress (78). On an ADMIN path that precision is the
 * point. On the MOUNT path it is an oracle: an adversary holding the decoy passphrase, who can run
 * the binary and read $?, learns whether a hardware/threshold factor is configured, whether keyslot
 * policies exist, and -- worst -- whether the passphrase they were given is a DURESS passphrase.
 *
 * Two shipped specs already require the opposite:
 *   docs/KEYSLOT-POLICY-DESIGN.md  -- expiry must be SILENT
 *   docs/DURESS-DISMOUNT-SPEC.md   -- a duress passphrase must be INDISTINGUISHABLE from a failure
 * so this is not a new policy; it is the code catching up with two documents.
 *
 * WHY THE PARTITION IS NOT "COLLAPSE EVERYTHING"
 *
 * Membership is decided by one question: can an adversary learn this by TRYING PASSPHRASES? If yes it
 * collapses; if no, collapsing costs diagnosability and buys no secrecy. VC_ERR_TAMPERED is the
 * interesting exclusion -- it reports that the MEDIUM was modified, which whoever modified it already
 * knows, and this fork deliberately surfaces it (v2 fail-closed reads). Collapsing it would silently
 * undo shipped tamper-evidence in exchange for nothing.
 *
 * WHAT THIS PROVES
 *   [1] every credential-dependent status maps to ONE code, ONE name and ONE string;
 *   [2] duress in particular is indistinguishable from a wrong passphrase on the mount path;
 *   [3] the non-credential statuses are NOT collapsed (specificity -- a partition that flattened
 *       everything would pass [1] and destroy diagnosability);
 *   [4] the collapse target is the stock "wrong password" answer, so the fork's mount path is
 *       indistinguishable from upstream VeraCrypt's rather than merely internally consistent;
 *   [5] the admin path still sees the fine-grained codes (the table is untouched);
 *   [6] a NEGATIVE CONTROL: a build that leaks the fine-grained code must FAIL this test. Without
 *       this arm the test cannot tell a working partition from a partition that is never called.
 *
 * ANCHOR CLASS: PROPERTY / [TWIN-ONLY]. This is fork policy, not a published standard; there is no
 * external vector set for "which errors may be distinguished". The cross-check is
 * verification/status_reference.py, which re-derives the same partition independently.
 */
#include <stdio.h>
#include <string.h>
#include "Common/VcStatus.h"

static int pass = 0, fail = 0;
static void ck (const char *what, int ok)
{
	printf ("  %s %s\n", ok ? "ok  " : "FAIL", what);
	if (ok) pass++; else fail++;
}

/* The credential-dependent set, written out literally rather than by calling the function under
   test -- otherwise the test would agree with a wrong implementation by construction. */
static const VcStatus CRED[] = {
	VC_ERR_WRONG_PASSWORD, VC_ERR_FACTOR_MISSING, VC_ERR_SLOT_EXPIRED,
	VC_ERR_SLOT_LOCKED,    VC_ERR_DURESS
};
static const VcStatus NONCRED[] = {
	VC_OK, VC_ERR_PARAM, VC_ERR_IO, VC_ERR_UNSUPPORTED, VC_ERR_INTERNAL, VC_ERR_TAMPERED
};
#define NCRED    ((int)(sizeof CRED    / sizeof CRED[0]))
#define NNONCRED ((int)(sizeof NONCRED / sizeof NONCRED[0]))

int main (void)
{
	int i;

	printf ("[1] every credential-dependent outcome collapses to one equivalence class\n");
	{
		const int  code = VcStatusExitCode (VcStatusMountSafe (CRED[0]));
		const char *nm  = VcStatusName     (VcStatusMountSafe (CRED[0]));
		const char *ds  = VcStatusString   (VcStatusMountSafe (CRED[0]));
		int same = 1;
		for (i = 0; i < NCRED; i++)
		{
			VcStatus m = VcStatusMountSafe (CRED[i]);
			if (VcStatusExitCode (m) != code)          same = 0;
			if (strcmp (VcStatusName   (m), nm) != 0)  same = 0;
			if (strcmp (VcStatusString (m), ds) != 0)  same = 0;
		}
		ck ("all 5 credential-dependent statuses share one exit code, name and string", same);
		printf ("       -> exit %d, name \"%s\"\n", code, nm);
	}

	printf ("[2] duress is indistinguishable from a wrong passphrase\n");
	ck ("duress maps to the same status as a wrong passphrase",
	    VcStatusMountSafe (VC_ERR_DURESS) == VcStatusMountSafe (VC_ERR_WRONG_PASSWORD));
	ck ("duress does not keep its own exit code on the mount path",
	    VcStatusExitCode (VcStatusMountSafe (VC_ERR_DURESS)) != VcStatusExitCode (VC_ERR_DURESS));
	ck ("the string \"duress\" never reaches a mount-path caller",
	    strstr (VcStatusName (VcStatusMountSafe (VC_ERR_DURESS)), "duress") == NULL);

	printf ("[3] SPECIFICITY — non-credential statuses are NOT collapsed\n");
	{
		int preserved = 1;
		for (i = 0; i < NNONCRED; i++)
			if (VcStatusMountSafe (NONCRED[i]) != NONCRED[i]) preserved = 0;
		ck ("param / io / unsupported / internal / tampered / ok pass through unchanged", preserved);
	}
	ck ("tamper detection survives the mount path (a different axis, not a credential oracle)",
	    VcStatusMountSafe (VC_ERR_TAMPERED) == VC_ERR_TAMPERED);

	printf ("[4] the collapse target is the stock \"wrong password\" answer\n");
	ck ("collapsed status == VC_ERR_WRONG_PASSWORD",
	    VcStatusMountSafe (VC_ERR_FACTOR_MISSING) == VC_ERR_WRONG_PASSWORD);

	printf ("[5] the admin path still sees the fine-grained taxonomy\n");
	{
		int distinct = 1;
		for (i = 0; i < NCRED; i++)
		{
			int j;
			for (j = i + 1; j < NCRED; j++)
				if (VcStatusExitCode (CRED[i]) == VcStatusExitCode (CRED[j])) distinct = 0;
		}
		ck ("the raw table still gives 5 distinct exit codes for admin/recovery use", distinct);
	}

	printf ("[6] negative control — a leaking build must fail\n");
	{
		/* Model the pre-fix behaviour: emit the raw status on the mount path. If the assertions in
		   [1] would still hold under that, they have no teeth. */
		int leaks_are_caught = 0;
		const int a = VcStatusExitCode (VC_ERR_DURESS);          /* what a leaking build emits */
		const int b = VcStatusExitCode (VC_ERR_WRONG_PASSWORD);
		if (a != b) leaks_are_caught = 1;
		ck ("raw statuses ARE distinguishable, so [1] is a real constraint", leaks_are_caught);
		printf ("       -> unpartitioned: duress=%d wrong_password=%d (an oracle)\n", a, b);
	}

	/* Machine-readable line for the Python cross-check. */
	printf ("MOUNTSAFE");
	for (i = 0; i < VC_STATUS_COUNT; i++)
		printf (" %d:%d", i, (int) VcStatusMountSafe ((VcStatus) i));
	printf ("\n");

	printf ("\nNO-ORACLE: %d passed, %d failed\n", pass, fail);
	return fail ? 1 : 0;
}
