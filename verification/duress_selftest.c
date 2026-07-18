/*
 * duress_selftest.c — self-contained verification for the duress-passphrase token.
 *
 * Layer 2 of the project's two-way convention: this harness links the REAL in-tree VeraCrypt
 * hmac_sha256 (Common/Pkcs5.c over Crypto/Sha2.c) and drives Common/DuressToken.c. Layer 1 is
 * duress_reference.py, an independent HMAC-SHA256 built on Python's hashlib; build_and_verify.sh
 * diffs the "REF" lines byte-for-byte.
 *
 * Checks:
 *   [C] DuressTokenDerive on a FIXED vector -> printed "REF" line (matched against Python).
 *   [D] DuressTokenCheck accepts the duress passphrase and rejects a wrong one.
 *   [E] DuressTokenMatch is exact (equal buffers match; a one-byte difference does not).
 */

#include <stdio.h>
#include <string.h>
#include "Common/DuressToken.h"

static void print_hex (const char *label, const unsigned char *p, int n)
{
	int i;
	printf ("%s", label);
	for (i = 0; i < n; i++)
		printf ("%02x", p[i]);
	printf ("\n");
}

/* ---- FIXED test vector, shared verbatim with duress_reference.py ---- */
#define SALT_LEN 16
static const char *PASS = "correct horse battery staple";

static void fill_salt (unsigned char salt[SALT_LEN])
{
	int i;
	for (i = 0; i < SALT_LEN; i++)
		salt[i] = (unsigned char) ((i * 7 + 3) & 0xff);
}

int main (void)
{
	unsigned char salt[SALT_LEN], tag[DURESS_TAG_SIZE];
	fill_salt (salt);

	/* [C] fixed-vector tag -> reproducible "REF" line for the Python cross-check */
	DuressTokenDerive (salt, SALT_LEN, (const unsigned char *) PASS, (int) strlen (PASS), tag);
	print_hex ("REF duress_tag = ", tag, DURESS_TAG_SIZE);

	/* [D] check accepts the real duress passphrase and rejects a wrong one */
	{
		int good = DuressTokenCheck (salt, SALT_LEN, (const unsigned char *) PASS, (int) strlen (PASS), tag);
		const char *wrong = "correct horse battery stapl3";
		int bad  = DuressTokenCheck (salt, SALT_LEN, (const unsigned char *) wrong, (int) strlen (wrong), tag);
		printf ("[D] accepts duress passphrase: %s\n", good ? "YES" : "NO");
		printf ("[D] rejects wrong passphrase: %s\n", !bad ? "YES" : "NO");
	}

	/* [E] constant-time match is exact */
	{
		unsigned char a[DURESS_TAG_SIZE], b[DURESS_TAG_SIZE];
		int i, eq, ne;
		for (i = 0; i < DURESS_TAG_SIZE; i++) { a[i] = (unsigned char) i; b[i] = (unsigned char) i; }
		eq = DuressTokenMatch (a, b, DURESS_TAG_SIZE);
		b[DURESS_TAG_SIZE - 1] ^= 0x01;
		ne = DuressTokenMatch (a, b, DURESS_TAG_SIZE);
		printf ("[E] equal buffers match: %s\n", eq ? "YES" : "NO");
		printf ("[E] one-byte difference rejected: %s\n", !ne ? "YES" : "NO");
	}

	return 0;
}
