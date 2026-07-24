/*
 * chacha20_libsodium_xcheck.c — anchor the in-tree ChaCha20 (src/Crypto/chacha256.c) to an implementation
 * this project did not write.
 *
 * WHY (anchor audit). In-tree ChaCha20 is load-bearing: it encrypts the keyslot VMK wrap (step [8]) and
 * backs the KeyScrub RAM-at-rest transform (step [6]). Both were checked only against our own Python.
 *
 * WHICH STANDARD — READ THIS BEFORE "FIXING" A MISMATCH. The audit first listed RFC 8439 Section 2.4.2 as
 * the anchor for this primitive. That was WRONG, and the mistake is instructive. ChaCha20 has two
 * incompatible framings of the last four state words:
 *
 *   original (Bernstein)  words 12,13 = 64-bit counter ; words 14,15 = 64-bit (8-byte) nonce
 *   RFC 8439 ("ietf")     word  12    = 32-bit counter ; words 13,14,15 = 96-bit (12-byte) nonce
 *
 * src/Crypto/chacha256.c is the ORIGINAL variant -- ChaCha256Init zeroes input_[12] and input_[13] and
 * copies exactly 8 nonce bytes into input_[14]. So RFC 8439's vectors CANNOT reproduce its keystream, and
 * a mismatch against them would be a category error, not a bug. VeraCrypt uses this for RNG and RAM
 * encryption, never for interop, so the original framing is a perfectly sound choice -- it simply is not
 * the IETF one.
 *
 * The matching oracle is libsodium's crypto_stream_chacha20 (NOT crypto_stream_chacha20_ietf), which
 * implements the same original framing with an 8-byte nonce and a counter starting at zero.
 *
 * Anchor class: THIRD-PARTY (see docs/VERIFICATION-ANCHORS.md). Verification-only; libsodium is never
 * linked into the product.
 */

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "Tcdefs.h"
#include "Crypto/chacha256.h"

static void tohex (const unsigned char *p, int n, char *o)
{ int i; for (i = 0; i < n; i++) sprintf (o + 2 * i, "%02x", p[i]); }

static int g_fail = 0;

static void run_case (const char *label, const unsigned char key[32], const unsigned char nonce[8], size_t len)
{
	unsigned char *zero = calloc (1, len), *mine = malloc (len), *theirs = malloc (len);
	ChaCha256Ctx ctx;
	char ha[65], hb[65];

	/* in-tree: encrypting zeroes yields the raw keystream */
	ChaCha256Init (&ctx, key, nonce, 20);
	ChaCha256Encrypt (&ctx, zero, len, mine);

	/* libsodium, original (non-ietf) framing, counter starts at 0 */
	crypto_stream_chacha20 (theirs, (unsigned long long) len, nonce, key);

	tohex (mine, len < 32 ? len : 32, ha);
	tohex (theirs, len < 32 ? len : 32, hb);
	if (memcmp (mine, theirs, len) == 0)
		printf ("    %-44s MATCH  (%4zu B) %s...\n", label, len, ha);
	else {
		printf ("    %-44s MISMATCH (%zu B)\n      in-tree   %s...\n      libsodium %s...\n", label, len, ha, hb);
		g_fail = 1;
	}
	free (zero); free (mine); free (theirs);
}

int main (void)
{
	unsigned char key[32], nonce[8];
	int i;

	if (sodium_init () < 0) { fprintf (stderr, "sodium_init failed\n"); return 2; }

	printf ("in-tree ChaCha20 (original 8-byte-nonce framing) vs libsodium crypto_stream_chacha20\n");

	/* all-zero key/nonce */
	memset (key, 0, 32); memset (nonce, 0, 8);
	run_case ("zero key, zero nonce", key, nonce, 128);

	/* RFC-8439-style key bytes 00..1f, but the ORIGINAL 8-byte nonce framing */
	for (i = 0; i < 32; i++) key[i] = (unsigned char) i;
	memset (nonce, 0, 8); nonce[7] = 0x4a;
	run_case ("key 00..1f, nonce 00..004a", key, nonce, 128);

	/* multi-block and non-block-multiple lengths (buffer/position handling) */
	run_case ("same, 64 B (exactly one block)", key, nonce, 64);
	run_case ("same, 63 B (partial block)", key, nonce, 63);
	run_case ("same, 65 B (block + 1)", key, nonce, 65);
	run_case ("same, 1000 B (many blocks)", key, nonce, 1000);

	/* varied key/nonce */
	for (i = 0; i < 32; i++) key[i] = (unsigned char) (0xff - i);
	for (i = 0; i < 8; i++) nonce[i] = (unsigned char) (0xa0 + i);
	run_case ("inverted key, nonce a0..a7", key, nonce, 256);

	if (g_fail) { printf ("CHACHA20 LIBSODIUM XCHECK: MISMATCH\n"); return 1; }
	printf ("CHACHA20 LIBSODIUM XCHECK: in-tree ChaCha20 == libsodium on all cases\n");
	return 0;
}
