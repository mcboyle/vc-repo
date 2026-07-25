/*
 * hctr2_module_test.c — the SHIPPABLE src/Crypto/Hctr2 against the OFFICIAL google/hctr2 vectors.
 *
 * WHAT THIS ADDS OVER STEP [26]. Step [26] proved the HCTR2 ALGORITHM in a PoC
 * (verification/hctr2_poc.c) against all 35 official vectors, using the table-driven in-tree Gladman
 * AES. This runs the SAME official vectors through the real compiled src/Crypto/Hctr2.o — the code
 * that would actually ship — which differs from the PoC in one cryptographically material way:
 *
 *     the block cipher is the CONSTANT-TIME src/Crypto/AesCt, not the table-driven AES.
 *
 * That substitution is exactly the kind of change that can silently break a mode (wrong key schedule,
 * wrong direction on the inverse cipher, endianness slip in the counter block) while still producing
 * plausible-looking ciphertext that round-trips. Reproducing the official vectors byte-for-byte is what
 * rules that out. It is the HCTR2 analogue of step [89], which did the same for Adiantum.
 *
 * ANCHOR CLASS: OFFICIAL — google/hctr2 test_vectors/ours/HCTR2/HCTR2_AES256.json, an artifact this
 * project did not author. Plus PROPERTY checks the vectors cannot express: wide-block diffusion, in-place
 * aliasing, tweak separation, and the fail-closed bounds.
 *
 * Build: verification/build_and_verify.sh step [105].
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "Crypto/Hctr2.h"
#include "hctr2_kats.h"

static int pass = 0, fail = 0;
static void check (const char *what, int ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

static int hexval (char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t unhex (const char *s, unsigned char *out)
{
	size_t n = 0;
	while (s[0] && s[1]) { out[n++] = (unsigned char) ((hexval (s[0]) << 4) | hexval (s[1])); s += 2; }
	return n;
}

static size_t diff_bytes (const unsigned char *a, const unsigned char *b, size_t n)
{
	size_t d = 0, i;
	for (i = 0; i < n; i++) if (a[i] != b[i]) d++;
	return d;
}

int main (void)
{
	printf ("  HCTR2 shippable module (src/Crypto/Hctr2.c) vs the OFFICIAL google/hctr2 vectors\n");

	static unsigned char key[64], twk[HCTR2_MAX_TWEAK + 16];
	static unsigned char pt[HCTR2_MAX_SECTOR + 16], ct[HCTR2_MAX_SECTOR + 16];
	static unsigned char got[HCTR2_MAX_SECTOR + 16], rt[HCTR2_MAX_SECTOR + 16];
	int i, encOk = 0, decOk = 0;

	/* ---- 1. every official vector, BOTH directions ------------------------------------------------ */
	printf ("  [1] all %d official AES-256 vectors, encrypt and decrypt\n", HCTR2_NKATS);
	for (i = 0; i < HCTR2_NKATS; i++) {
		Hctr2Key hk;
		size_t klen = unhex (hctr2_kats[i][0], key);
		size_t tlen = unhex (hctr2_kats[i][1], twk);
		size_t plen = unhex (hctr2_kats[i][2], pt);
		size_t clen = unhex (hctr2_kats[i][3], ct);

		if (klen != 32 || plen != clen) { printf ("    FAIL vector %d malformed\n", i); fail++; continue; }

		Hctr2Init (&hk, key);
		if (!Hctr2Encrypt (&hk, twk, tlen, pt, plen, got)) { printf ("    FAIL vector %d encrypt refused\n", i); fail++; continue; }
		if (memcmp (got, ct, clen) == 0) encOk++;
		else printf ("    FAIL vector %d: ciphertext mismatch (len=%u tweak=%u)\n", i, (unsigned) plen, (unsigned) tlen);

		if (!Hctr2Decrypt (&hk, twk, tlen, ct, clen, rt)) { printf ("    FAIL vector %d decrypt refused\n", i); fail++; continue; }
		if (memcmp (rt, pt, plen) == 0) decOk++;
		else printf ("    FAIL vector %d: decrypt did not recover the plaintext\n", i);
	}
	check ("every official vector encrypts to the published ciphertext", encOk == HCTR2_NKATS);
	check ("every official vector decrypts back to the published plaintext", decOk == HCTR2_NKATS);

	/* ---- 2. the wide-block property — the entire reason to use this mode -------------------------- */
	printf ("  [2] wide-block diffusion (the property XTS does NOT have)\n");
	{
		Hctr2Key hk;
		const size_t SEC = 512;
		unsigned char k[32], t[8], a[512], b[512];
		size_t j;
		for (j = 0; j < sizeof k; j++) k[j] = (unsigned char) (j * 7 + 1);
		for (j = 0; j < sizeof t; j++) t[j] = (unsigned char) j;
		for (j = 0; j < SEC; j++) a[j] = (unsigned char) j;
		memcpy (b, a, SEC);
		b[SEC / 2] ^= 0x01;                       /* ONE bit, mid-sector */

		Hctr2Init (&hk, k);
		Hctr2Encrypt (&hk, t, sizeof t, a, SEC, a);
		Hctr2Encrypt (&hk, t, sizeof t, b, SEC, b);

		{
			size_t d = diff_bytes (a, b, SEC);
			printf ("    one plaintext bit flipped -> %u of %u ciphertext bytes differ\n",
			        (unsigned) d, (unsigned) SEC);
			check ("a 1-bit plaintext change randomises the WHOLE sector (>90% of bytes)", d > (SEC * 9) / 10);
			check ("...and is not confined to a 16-byte block (as XTS would be)", d > 16);
		}
	}

	/* ---- 3. in-place aliasing (in == out), which the vectors never exercise ----------------------- */
	printf ("  [3] in-place operation\n");
	{
		Hctr2Key hk;
		unsigned char k[32], t[8], buf[256], orig[256], sep[256];
		size_t j;
		for (j = 0; j < sizeof k; j++) k[j] = (unsigned char) (0xA0 + j);
		for (j = 0; j < sizeof t; j++) t[j] = (unsigned char) (0x50 + j);
		for (j = 0; j < sizeof buf; j++) buf[j] = (unsigned char) (j * 13 + 5);
		memcpy (orig, buf, sizeof buf);

		Hctr2Init (&hk, k);
		Hctr2Encrypt (&hk, t, sizeof t, orig, sizeof orig, sep);   /* separate buffers */
		Hctr2Encrypt (&hk, t, sizeof t, buf, sizeof buf, buf);     /* in place          */
		check ("in-place encrypt == separate-buffer encrypt", memcmp (buf, sep, sizeof buf) == 0);

		Hctr2Decrypt (&hk, t, sizeof t, buf, sizeof buf, buf);
		check ("in-place decrypt(encrypt(x)) == x", memcmp (buf, orig, sizeof orig) == 0);
	}

	/* ---- 4. the tweak actually separates ---------------------------------------------------------- */
	printf ("  [4] tweak separation\n");
	{
		Hctr2Key hk;
		unsigned char k[32], t1[8], t2[8], x[128], y[128];
		size_t j;
		for (j = 0; j < sizeof k; j++) k[j] = (unsigned char) (j ^ 0x5a);
		for (j = 0; j < sizeof t1; j++) { t1[j] = (unsigned char) j; t2[j] = (unsigned char) j; }
		t2[0] ^= 0x01;
		for (j = 0; j < sizeof x; j++) { x[j] = 0xC3; y[j] = 0xC3; }

		Hctr2Init (&hk, k);
		Hctr2Encrypt (&hk, t1, sizeof t1, x, sizeof x, x);
		Hctr2Encrypt (&hk, t2, sizeof t2, y, sizeof y, y);
		check ("identical plaintext under a 1-bit-different tweak -> different ciphertext",
		       memcmp (x, y, sizeof x) != 0);
	}

	/* ---- 5. fail closed on out-of-range input ----------------------------------------------------- */
	printf ("  [5] bounds are refused, not truncated\n");
	{
		Hctr2Key hk;
		unsigned char k[32], t[8];
		static unsigned char big[HCTR2_MAX_SECTOR + 32];
		size_t j;
		for (j = 0; j < sizeof k; j++) k[j] = (unsigned char) j;
		memset (t, 0, sizeof t);
		memset (big, 0, sizeof big);
		Hctr2Init (&hk, k);

		check ("a length below one block is REFUSED",
		       Hctr2Encrypt (&hk, t, sizeof t, big, HCTR2_MIN_LEN - 1, big) == 0);
		check ("a length above HCTR2_MAX_SECTOR is REFUSED",
		       Hctr2Encrypt (&hk, t, sizeof t, big, HCTR2_MAX_SECTOR + 16, big) == 0);
		check ("an oversized tweak is REFUSED",
		       Hctr2Encrypt (&hk, big, HCTR2_MAX_TWEAK + 1, big, 256, big) == 0);
		check ("exactly one block (the minimum) is ACCEPTED",
		       Hctr2Encrypt (&hk, t, sizeof t, big, HCTR2_MIN_LEN, big) == 1);
	}

	printf ("  HCTR2 MODULE: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  HCTR2 MODULE TEST FAILED\n"); return 1; }
	printf ("  HCTR2 MODULE TEST PASSED\n");
	return 0;
}
