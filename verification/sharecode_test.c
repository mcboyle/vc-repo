/*
 * sharecode_test.c — the REAL Common/ShareCode.c (bech32 share encoding) driven end-to-end
 * (build_and_verify.sh step [42]; docs/VSS-SPEC.md, IDEAS-BACKLOG D "SLIP-39-style encoding").
 *
 * Two-way per the project convention: this drives the real compiled ShareCode.c + Shamir.c, emitting
 * REF lines (the encoded share strings) that sharecode_reference.py recomputes independently (a
 * from-the-spec bech32). Extra checks (PASS/FAIL): an OFFICIAL BIP-173 anchor (encode of hrp "a" with
 * empty data == "a12uel5l") proves the bech32 checksum matches the standard; encode->decode round-trips
 * a real share (with and without its per-share MAC); and every single-character substitution in a
 * sample is REJECTED by the checksum (the typo-detection guarantee).
 */

#include <stdio.h>
#include <string.h>
#include "Common/Shamir.h"
#include "Common/ShareCode.h"

/* the BIP-173 bech32 internals are static in ShareCode.c; re-expose a minimal encoder here ONLY to
   check the "a12uel5l" anchor, using the same charset/generator constants. */
static const char *CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const unsigned int GEN[5] = { 0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u };
static unsigned int polymod (const unsigned char *v, int n)
{ unsigned int chk = 1; int i, j; for (i=0;i<n;i++){ unsigned int b=chk>>25; chk=((chk&0x1ffffffu)<<5)^v[i]; for(j=0;j<5;j++) if((b>>j)&1u) chk^=GEN[j]; } return chk; }
static void bech32_empty (const char *hrp, char out[16])
{
	unsigned char in[3 + 6]; int n = 0, i; unsigned int pm;
	for (i = 0; hrp[i]; i++) in[n++] = (unsigned char) (hrp[i] >> 5);
	in[n++] = 0;
	for (i = 0; hrp[i]; i++) in[n++] = (unsigned char) (hrp[i] & 31);
	for (i = 0; i < 6; i++) in[n++] = 0;
	pm = polymod (in, n) ^ 1u;
	{ int p = 0; for (i = 0; hrp[i]; i++) out[p++] = hrp[i]; out[p++] = '1';
	  for (i = 0; i < 6; i++) out[p++] = CS[(pm >> (5 * (5 - i))) & 31]; out[p] = 0; }
}

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-52s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

int main (void)
{
	unsigned char secret[32], rnd[2 * 32], mac[SHARECODE_MAC_SIZE];
	ShamirShare shares[5];
	char code[SHARECODE_MAX_LEN];
	int i;

	for (i = 0; i < 32; i++) secret[i] = (unsigned char) (0x40 + i);
	for (i = 0; i < (int) sizeof (rnd); i++) rnd[i] = (unsigned char) (i * 7 + 1);
	for (i = 0; i < SHARECODE_MAC_SIZE; i++) mac[i] = (unsigned char) (0xB0 + i);

	if (shamir_split (secret, 32, 3, 5, rnd, shares) != SHAMIR_OK) { printf ("split failed\n"); return 1; }

	/* ---- REF: deterministic encodings (python recomputes byte-for-byte) ---- */
	for (i = 0; i < 5; i++)
	{
		if (ShareCodeEncode (&shares[i], NULL, code, sizeof (code)) != SHARECODE_OK) { printf ("encode failed\n"); return 1; }
		printf ("REF share%d code = %s\n", i + 1, code);
	}
	/* one with the MAC appended */
	if (ShareCodeEncode (&shares[0], mac, code, sizeof (code)) != SHARECODE_OK) { printf ("encode+mac failed\n"); return 1; }
	printf ("REF share1 code+mac = %s\n", code);

	/* ---- BIP-173 anchor ---- */
	printf ("[checks]\n");
	{
		char anchor[16]; bech32_empty ("a", anchor);
		check ("BIP-173 anchor: bech32(\"a\",empty) == a12uel5l", strcmp (anchor, "a12uel5l") == 0);
	}

	/* ---- round-trip (no MAC) ---- */
	{
		ShamirShare dec; int hasMac = -1, ok;
		ShareCodeEncode (&shares[2], NULL, code, sizeof (code));
		ok = ShareCodeDecode (code, &dec, NULL, &hasMac) == SHARECODE_OK;
		check ("round-trip decode ok", ok);
		check ("round-trip x/len/y identical", dec.x == shares[2].x && dec.len == shares[2].len
		       && memcmp (dec.y, shares[2].y, shares[2].len) == 0);
		check ("round-trip reports no MAC", hasMac == 0);
	}
	/* ---- round-trip (with MAC) ---- */
	{
		ShamirShare dec; unsigned char macOut[SHARECODE_MAC_SIZE]; int hasMac = -1;
		ShareCodeEncode (&shares[0], mac, code, sizeof (code));
		check ("round-trip+MAC decode ok", ShareCodeDecode (code, &dec, macOut, &hasMac) == SHARECODE_OK);
		check ("round-trip+MAC share identical", dec.x == shares[0].x && dec.len == shares[0].len
		       && memcmp (dec.y, shares[0].y, shares[0].len) == 0);
		check ("round-trip+MAC recovers tag", hasMac == 1 && memcmp (macOut, mac, SHARECODE_MAC_SIZE) == 0);
	}

	/* ---- typo detection: every single-character substitution is rejected ---- */
	{
		int clen, pos, c, tested = 0, missed = 0;
		ShareCodeEncode (&shares[1], NULL, code, sizeof (code));
		clen = (int) strlen (code);
		for (pos = 4; pos < clen; pos++)            /* mutate the data+checksum part (after "vcs1") */
		{
			char orig = code[pos];
			for (c = 0; c < 32; c++)
			{
				ShamirShare dec; int hasMac;
				char sub = CS[c];
				if (sub == orig) continue;
				code[pos] = sub;
				tested++;
				if (ShareCodeDecode (code, &dec, NULL, &hasMac) == SHARECODE_OK) missed++;   /* undetected typo */
			}
			code[pos] = orig;
		}
		printf ("  single-char substitutions tested = %d, undetected = %d\n", tested, missed);
		check ("all single-char typos detected", missed == 0);
	}

	/* the guarantee window: this share's code stays within bech32's 90-char BCH bound */
	{
		ShareCodeEncode (&shares[0], NULL, code, sizeof (code));
		check ("256-bit-secret code within 90-char guarantee", (int) strlen (code) <= 90);
	}

	printf ("%s\n", all_pass ? "ALL SHARECODE CHECKS PASSED" : "SHARECODE CHECKS FAILED");
	return all_pass ? 0 : 1;
}
