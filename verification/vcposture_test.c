/*
 * vcposture_test.c — security-posture report (ROI item 18) over the real VcPosture + VcJson.
 *
 * Prints the posture JSON for whatever feature flags this translation unit was compiled with. The
 * suite compiles it three ways and checks the report tracks the build:
 *   (A) with a subset of features ON  -> those fields true, the rest false;
 *   (B) with NO features (stock)      -> every field false, features_on:0, hardened:false;
 *   (C) negative control -DVP_NEGCTL, built with NO features -> the report LIES (fields true),
 *       proving that in the honest build (B) the false values genuinely come from the compile guards.
 * The JSON is also validated by python's parser (reused json oracle) for well-formedness.
 */
#include <stdio.h>
#include "Common/VcPosture.h"

int main (void)
{
	char buf[512];
	if (VcPostureReportJson (buf, sizeof buf) != 0) { printf ("OVERFLOW\n"); return 1; }
	printf ("%s\n", buf);
	printf ("COUNT=%d\n", VcPostureFeatureCount ());
	return 0;
}
