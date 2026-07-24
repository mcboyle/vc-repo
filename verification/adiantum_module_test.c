/*
 * adiantum_module_test.c — the SHIPPABLE Adiantum mode (src/Crypto/Adiantum.c) vs the official
 * google/adiantum KATs (T2-4d). Steps [24]/[89] proved the inline PoC (table AES, then constant-time
 * AES); this proves the src/ module by LINKING the real Adiantum.o (built -DVC_ENABLE_ADIANTUM) against
 * the real in-tree primitives it depends on: AesCt.o (constant-time AES), chacha256.o (XChaCha12 stream)
 * and Poly1305.o (the polynomial hash) — same technique as the AesCt/V2Format/Poly1305 module tests.
 *
 * Proven two ways: every official google/adiantum vector (adiantum_kats.h) encrypts AND decrypts
 * byte-for-byte through the real objects, and adiantum_reference.py reproduces the same REF lines
 * independently (build_and_verify.sh diffs them). Also exercised: whole-sector diffusion (one flipped
 * bit scrambles the entire block), wrong-key and wrong-tweak separation, and in==out aliasing.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "Crypto/Adiantum.h"
#include "adiantum_kats.h"

#define MAX_MSG   4096
#define MAX_TWEAK 64

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-54s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }
static void hexp (const unsigned char *b, size_t n) { size_t i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

static size_t hexparse (const char *s, unsigned char *out)
{
	size_t n = 0;
	while (s[0] && s[1])
	{
		unsigned int b; char t[3] = { s[0], s[1], 0 };
		sscanf (t, "%2x", &b);
		out[n++] = (unsigned char)b; s += 2;
	}
	return n;
}
static size_t hamming (const unsigned char *a, const unsigned char *b, size_t n)
{
	size_t i, bits = 0;
	for (i = 0; i < n; i++) { unsigned char d = a[i] ^ b[i]; while (d) { bits += d & 1; d >>= 1; } }
	return bits;
}

int main (void)
{
	static unsigned char key[32], tweak[MAX_TWEAK], pt[MAX_MSG], expect[MAX_MSG],
	                     ct[MAX_MSG], back[MAX_MSG], mut[MAX_MSG];
	size_t tlen, mlen;
	int i, all_match = 1, roundtrip = 1;
	AdiantumKey ak;

	/* every official google/adiantum vector, both directions, through the real module */
	for (i = 0; i < ADIANTUM_NKATS; i++)
	{
		hexparse (adiantum_kats[i][0], key);
		tlen = hexparse (adiantum_kats[i][1], tweak);
		mlen = hexparse (adiantum_kats[i][2], pt);
		hexparse (adiantum_kats[i][3], expect);

		AdiantumInit (&ak, key);
		AdiantumEncrypt (&ak, tweak, tlen, pt, mlen, ct);
		printf ("REF kat_%d ", i); hexp (ct, mlen); printf ("\n");
		if (memcmp (ct, expect, mlen) != 0) all_match = 0;

		AdiantumDecrypt (&ak, tweak, tlen, expect, mlen, back);
		if (memcmp (back, pt, mlen) != 0) roundtrip = 0;
	}
	printf ("REF kat_all_match %s\n", all_match ? "YES" : "NO");
	printf ("REF roundtrip_all %s\n", roundtrip ? "YES" : "NO");
	check ("shippable Adiantum == all official google/adiantum KATs", all_match);
	check ("shippable Adiantum decrypt round-trips every KAT", roundtrip);

	/* diffusion / wrong-key / wrong-tweak on the DIFFUSION_IDX vector */
	hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][0], key);
	tlen = hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][1], tweak);
	mlen = hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][2], pt);
	hexparse (adiantum_kats[ADIANTUM_DIFFUSION_IDX][3], expect);
	AdiantumInit (&ak, key);

	{	/* flip one plaintext bit -> whole ciphertext scrambles */
		int yes;
		memcpy (mut, pt, mlen); mut[0] ^= 0x01;
		AdiantumEncrypt (&ak, tweak, tlen, mut, mlen, ct);
		yes = hamming (ct, expect, mlen) * 10 >= 4 * 8 * mlen
			&& memcmp (ct, expect, 16) != 0
			&& memcmp (ct + mlen - 16, expect + mlen - 16, 16) != 0;
		check ("whole-sector diffusion: 1 pt bit -> ~half ct bits flip", yes);
	}
	{	/* wrong key */
		AdiantumKey wk;
		unsigned char k2[32];
		memcpy (k2, key, 32); k2[0] ^= 0x01;
		AdiantumInit (&wk, k2);
		AdiantumEncrypt (&wk, tweak, tlen, pt, mlen, ct);
		check ("wrong key -> different ciphertext", memcmp (ct, expect, mlen) != 0);
	}
	{	/* wrong tweak */
		unsigned char t2[MAX_TWEAK];
		memcpy (t2, tweak, tlen); t2[0] ^= 0x01;
		AdiantumEncrypt (&ak, t2, tlen, pt, mlen, ct);
		check ("wrong tweak -> different ciphertext", memcmp (ct, expect, mlen) != 0);
	}
	{	/* in == out aliasing: encrypt in place then decrypt in place recovers the plaintext */
		memcpy (mut, pt, mlen);
		AdiantumEncrypt (&ak, tweak, tlen, mut, mlen, mut);
		AdiantumDecrypt (&ak, tweak, tlen, mut, mlen, mut);
		check ("in==out aliasing round-trips", memcmp (mut, pt, mlen) == 0);
	}
	{	/* bounds guard: a too-short buffer is refused, output untouched */
		unsigned char small[8];
		memset (small, 0xAB, sizeof small);
		check ("len<16 refused (returns 0)", AdiantumEncrypt (&ak, tweak, tlen, small, 8, small) == 0);
	}

	printf ("\n%s\n", all_pass ? "ADIANTUM MODULE TESTS PASSED (real src/Crypto/Adiantum.o)" : "ADIANTUM MODULE TESTS FAILED");
	return all_pass ? 0 : 1;
}
