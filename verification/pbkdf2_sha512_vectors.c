/*
 * pbkdf2_sha512_vectors.c — anchor the SHIPPING PBKDF2-HMAC-SHA512 (`derive_key_sha512`) to published
 * vectors + an independent third-party implementation.
 *
 * WHY (anchor audit). `derive_key_sha512` in src/Common/Pkcs5.c is load-bearing in this fork: it is the
 * shipping `KeyslotKdfSha512` (src/Common/KeyslotKdf.c) that derives the wrapping key for EVERY keyslot
 * VMK, and it is a mountable volume PRF. Before this harness, nothing in the suite checked it against any
 * external artifact — steps [8]/[9] exercise it only inside fork-specific compositions cross-checked
 * against our OWN Python reference.
 *
 * That is precisely the pattern that hid the ristretto255 hash-to-group defect found at step [94]: a
 * self-written twin agrees with the C for the same wrong reason, because both encode the same reading of
 * the spec. An independent, widely-deployed implementation cannot collude that way.
 *
 * WHAT THIS PROVES:
 *   (1) Hard KATs — published PBKDF2-HMAC-SHA512 vectors for P="password", S="salt", c=1/2/4096, dkLen=64.
 *       (Each was corroborated against OpenSSL before being embedded here, so a mis-transcribed constant
 *       cannot silently become the thing we test against.)
 *   (2) Third-party agreement — every case below is also emitted as a `REF` line and diffed by the suite
 *       step against Python's hashlib.pbkdf2_hmac (OpenSSL), an implementation this project did not write.
 *   (3) Edge shapes where PBKDF2 composition bugs actually live: dkLen not a multiple of the hash size
 *       (partial final block), dkLen spanning several blocks (block-index counter), and long password/salt.
 *
 * Anchor class: OFFICIAL-VECTOR + THIRD-PARTY (see docs/VERIFICATION-ANCHORS.md).
 */

#include <stdio.h>
#include <string.h>
#include "Tcdefs.h"
#include "Pkcs5.h"

static void tohex (const unsigned char *p, int n, char *out)
{ int i; for (i = 0; i < n; i++) sprintf (out + 2 * i, "%02x", p[i]); }

/* Published PBKDF2-HMAC-SHA512 vectors, P="password", S="salt", dkLen=64. Corroborated vs OpenSSL. */
static const struct { uint32 iter; const char *dk; } KAT[] = {
	{ 1,    "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
	        "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce" },
	{ 2,    "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
	        "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e" },
	{ 4096, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
	        "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5" },
};

/* Extra shapes cross-checked against OpenSSL by the suite step (emitted as REF lines). */
static const struct { const char *pwd; const char *salt; uint32 iter; int dklen; } CASES[] = {
	{ "password", "salt", 1,    64  },
	{ "password", "salt", 2,    64  },
	{ "password", "salt", 4096, 64  },
	{ "password", "salt", 4096, 100 },  /* partial final block (100 = 64 + 36) */
	{ "password", "salt", 1,    32  },  /* truncated single block */
	{ "password", "salt", 16,   200 },  /* spans 4 blocks — exercises the block-index counter */
	{ "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 64 },
	{ "p", "s", 1, 64 },
	{ "", "salt", 1, 64 },              /* zero-length password */
	{ "password", "", 1, 64 },          /* zero-length salt */
};

int main (void)
{
	unsigned char dk[256];
	char hex[513];
	int fail = 0, i;

	/* (1) hard KATs */
	for (i = 0; i < (int)(sizeof KAT / sizeof KAT[0]); i++)
	{
		derive_key_sha512 ((const unsigned char *) "password", 8,
		                   (const unsigned char *) "salt", 4,
		                   KAT[i].iter, dk, 64, NULL);
		tohex (dk, 64, hex);
		if (strcmp (hex, KAT[i].dk) != 0)
		{
			printf ("KAT c=%u MISMATCH\n  got %s\n  exp %s\n", (unsigned) KAT[i].iter, hex, KAT[i].dk);
			fail = 1;
		}
		else
			printf ("PBKDF2-HMAC-SHA512 published KAT c=%-4u dkLen=64  MATCH\n", (unsigned) KAT[i].iter);
	}

	/* (2)+(3) REF lines for the third-party (OpenSSL) diff */
	for (i = 0; i < (int)(sizeof CASES / sizeof CASES[0]); i++)
	{
		int pl = (int) strlen (CASES[i].pwd), sl = (int) strlen (CASES[i].salt);
		derive_key_sha512 ((const unsigned char *) CASES[i].pwd, pl,
		                   (const unsigned char *) CASES[i].salt, sl,
		                   CASES[i].iter, dk, CASES[i].dklen, NULL);
		tohex (dk, CASES[i].dklen, hex);
		printf ("REF %s|%s|%u|%d=%s\n", CASES[i].pwd, CASES[i].salt,
		        (unsigned) CASES[i].iter, CASES[i].dklen, hex);
	}

	if (fail) { printf ("PBKDF2 SHA512 VECTORS: FAILED\n"); return 1; }
	printf ("PBKDF2 SHA512 VECTORS: published KATs reproduced by the real derive_key_sha512\n");
	return 0;
}
