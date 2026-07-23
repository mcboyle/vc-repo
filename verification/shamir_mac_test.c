/*
 * shamir_mac_test.c — keyed per-share MAC over the REAL Common/Shamir.c + Common/ShamirMac.c
 * (build_and_verify.sh step [40]; docs/VSS-SPEC.md, IDEAS-BACKLOG §D).
 *
 * Two-way per the project convention: this drives the real compiled modules (Shamir split over
 * GF(2^8) + HMAC-SHA256 per share over the real Sha2.c), emitting REF lines (the per-share tags)
 * that shamir_mac_reference.py recomputes independently (stdlib hmac + a reimplemented GF(2^8)
 * Shamir split). Behavioural checks (PASS/FAIL): honest shares verify; a one-bit-flipped share, a
 * truncated share, a swapped-x share, and a fabricated share are all REJECTED; the wrong MAC key
 * rejects; and a below-threshold combine of MAC-valid shares still yields the wrong secret (the MAC
 * authenticates shares, it does not substitute for the threshold).
 */

#include <stdio.h>
#include <string.h>
#include "Common/Shamir.h"
#include "Common/ShamirMac.h"

#define SEC_LEN 32
#define THRESH  3
#define NSH     5

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-48s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

static void phex (const char *label, const unsigned char *p, int n)
{ int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

int main (void)
{
	unsigned char secret[SEC_LEN], rnd[(THRESH-1)*SEC_LEN], macKey[SHAMIR_MAC_KEY_SIZE];
	unsigned char tags[NSH * SHAMIR_MAC_TAG_SIZE];
	ShamirShare shares[NSH];
	int i;

	/* deterministic inputs so the reference reproduces the tags byte-for-byte */
	for (i = 0; i < SEC_LEN; i++) secret[i] = (unsigned char) (0x40 + i);
	for (i = 0; i < (int) sizeof (rnd); i++) rnd[i] = (unsigned char) (i * 7 + 1);
	for (i = 0; i < SHAMIR_MAC_KEY_SIZE; i++) macKey[i] = (unsigned char) (0x11 * (i + 1));

	if (shamir_split (secret, SEC_LEN, THRESH, NSH, rnd, shares) != SHAMIR_OK)
		{ printf ("split failed\n"); return 1; }

	ShamirMacAll (macKey, shares, NSH, tags);
	for (i = 0; i < NSH; i++)
	{
		char lbl[32]; sprintf (lbl, "REF share%d tag = ", i + 1);
		phex (lbl, tags + i * SHAMIR_MAC_TAG_SIZE, SHAMIR_MAC_TAG_SIZE);
	}

	printf ("[behaviour]\n");
	check ("all honest shares verify", ShamirVerifyAll (macKey, shares, NSH, tags) == 1);

	/* one-bit flip in share 2's y[0] -> rejected */
	{
		ShamirShare bad = shares[1];
		bad.y[0] ^= 0x01;
		check ("bit-flipped share rejected", ShamirShareVerify (macKey, &bad, tags + 1 * SHAMIR_MAC_TAG_SIZE) == 0);
	}
	/* truncated share (len shortened) -> rejected (len is authenticated) */
	{
		ShamirShare bad = shares[2];
		bad.len -= 1;
		check ("truncated share rejected", ShamirShareVerify (macKey, &bad, tags + 2 * SHAMIR_MAC_TAG_SIZE) == 0);
	}
	/* x-relabelled share (share 3's y with share 4's x) -> rejected (x is authenticated) */
	{
		ShamirShare bad = shares[2];
		bad.x = shares[3].x;
		check ("x-relabelled share rejected", ShamirShareVerify (macKey, &bad, tags + 2 * SHAMIR_MAC_TAG_SIZE) == 0);
	}
	/* fabricated share (attacker picks x, random y) -> no valid tag exists under macKey */
	{
		ShamirShare forged; int j;
		forged.x = 200; forged.len = SEC_LEN;
		for (j = 0; j < SEC_LEN; j++) forged.y[j] = (unsigned char) (0xA5 ^ j);
		/* attacker cannot produce the tag; verifying against ANY real tag fails */
		check ("fabricated share rejected", ShamirShareVerify (macKey, &forged, tags + 0) == 0);
	}
	/* wrong MAC key rejects an otherwise-honest share */
	{
		unsigned char wrongKey[SHAMIR_MAC_KEY_SIZE];
		memcpy (wrongKey, macKey, sizeof (wrongKey)); wrongKey[0] ^= 0x80;
		check ("wrong MAC key rejects", ShamirShareVerify (wrongKey, &shares[0], tags + 0) == 0);
	}
	/* the MAC authenticates shares; it does NOT replace the threshold: a below-threshold set of
	   MAC-valid shares still reconstructs the wrong secret */
	{
		unsigned char out[SEC_LEN]; int outLen; ShamirShare two[2];
		two[0] = shares[0]; two[1] = shares[1];
		check ("2 MAC-valid shares still verify", ShamirShareVerify (macKey, &two[0], tags + 0)
		       && ShamirShareVerify (macKey, &two[1], tags + SHAMIR_MAC_TAG_SIZE));
		shamir_combine (two, 2, out, &outLen);
		check ("below-threshold combine still wrong", memcmp (out, secret, SEC_LEN) != 0);
	}

	printf ("%s\n", all_pass ? "ALL SHAMIR MAC CHECKS PASSED" : "SHAMIR MAC CHECKS FAILED");
	return all_pass ? 0 : 1;
}
