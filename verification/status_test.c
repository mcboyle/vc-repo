/*
 * status_test.c — structured error taxonomy / stable exit codes (ROI item 47) over real VcStatus.c.
 *
 * Verifies the contract scripts depend on: every status has a name + description + exit code; error
 * exit codes are distinct and non-zero; names are unique; an out-of-range status falls back safely.
 * The "REF" lines (name -> exit code) are diffed byte-for-byte against status_reference.py — the
 * layer-1 independent pin of the exit-code contract. A renumber in VcStatus.c breaks that diff, which
 * IS the negative control (the stability guarantee has teeth).
 */
#include <stdio.h>
#include <string.h>
#include "Common/VcStatus.h"

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-48s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }

int main (void)
{
	int i, j;

	/* every status resolves to non-NULL name/desc and VC_OK is the only zero exit code */
	{
		int okzero = 1, others_nonzero = 1, names_ok = 1;
		for (i = 0; i < VC_STATUS_COUNT; i++) {
			if (!VcStatusName ((VcStatus) i) || !VcStatusString ((VcStatus) i)) names_ok = 0;
			if (i == VC_OK && VcStatusExitCode ((VcStatus) i) != 0) okzero = 0;
			if (i != VC_OK && VcStatusExitCode ((VcStatus) i) == 0) others_nonzero = 0;
		}
		check ("every status has a name + description", names_ok);
		check ("VC_OK exit code is 0", okzero);
		check ("every error exit code is non-zero", others_nonzero);
	}

	/* error exit codes distinct; names distinct */
	{
		int excol = 0, namecol = 0;
		for (i = 1; i < VC_STATUS_COUNT; i++)
			for (j = i + 1; j < VC_STATUS_COUNT; j++) {
				if (VcStatusExitCode ((VcStatus) i) == VcStatusExitCode ((VcStatus) j)) excol = 1;
				if (strcmp (VcStatusName ((VcStatus) i), VcStatusName ((VcStatus) j)) == 0) namecol = 1;
			}
		check ("error exit codes are pairwise distinct", !excol);
		check ("status names are pairwise distinct", !namecol);
	}

	/* out-of-range status maps to the internal-error fallback (no crash, defined behaviour) */
	check ("out-of-range status falls back to internal", VcStatusExitCode ((VcStatus) 999) == VcStatusExitCode (VC_ERR_INTERNAL));

	/* REF lines for the layer-1 python cross-check (pins the exit-code contract) */
	for (i = 0; i < VC_STATUS_COUNT; i++)
		printf ("REF %s %d\n", VcStatusName ((VcStatus) i), VcStatusExitCode ((VcStatus) i));

	printf ("\n%s\n", all_pass ? "PASS: error taxonomy is complete, distinct, and stable"
	                           : "FAIL: status taxonomy");
	return all_pass ? 0 : 1;
}
