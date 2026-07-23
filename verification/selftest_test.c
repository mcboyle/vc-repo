/*
 * selftest_test.c — exercises the real Common/SelfTest.c (ROI item 17).
 *
 * Layer 2 only: this drives the shipping VcForkSelfTest over the REAL compiled Sha3/Sha2/t1ha objects.
 * The KATs themselves are the independent references (FIPS-202 SHA3-512(""), FIPS-180-4 SHA-256("abc"),
 * plus a cross-compiler t1ha2 anchor). The negative control is a SECOND build of the same module with
 * -DVC_SELFTEST_CORRUPT, which perturbs one expected value: the self-test MUST then report a failure,
 * proving it would catch a miscompiled/corrupted crypto build at mount rather than pass vacuously.
 */
#include <stdio.h>
#include "Common/SelfTest.h"

int main (void)
{
	int r = VcForkSelfTest ();
#if defined(VC_SELFTEST_CORRUPT)
	/* negative control: the corrupted build must FAIL, and specifically flag SHA3-512 */
	printf ("NEGCTL self-test result = 0x%02x\n", r);
	printf ("NEGCTL detects corruption: %s\n", (r & VC_SELFTEST_SHA3_512) ? "YES" : "NO");
	return (r & VC_SELFTEST_SHA3_512) ? 0 : 1;   /* exit 0 == the control correctly detected the fault */
#else
	printf ("self-test result = 0x%02x\n", r);
	printf ("all fork-primitive KATs pass: %s\n", r == 0 ? "YES" : "NO");
	return r == 0 ? 0 : 1;
#endif
}
