/*
 * persector_poc.c — per-sector authentication (docs/PERSECTOR-AUTH-SPEC.md,
 * IDEAS-BACKLOG.md A). dm-integrity-style tamper detection: one Poly1305 tag per
 * sector, stored in a separate tag area, computed over the sector CIPHERTEXT
 * (encrypt-then-MAC) and BOUND to the sector index.
 *
 *   nonce_i = le64(sector_index)                 # distinct per sector
 *   otk_i   = ChaCha20(sector_mac_key, nonce_i)[0..32]
 *   tag_i   = Poly1305(otk_i, ciphertext_i)
 *
 * Because the nonce IS the sector index, every sector gets its own one-time
 * Poly1305 key. That buys two properties a whole-area MAC cannot:
 *   - per-sector independence: tampering sector i does not disturb sector j;
 *   - relocation resistance: moving a valid (ciphertext, tag) to another sector
 *     verifies under the wrong otk and is rejected -- XTS's per-sector tweak
 *     hides this only until an attacker copies whole sectors around.
 *
 * Drives the REAL in-tree Crypto/chacha256.c + the step-18/step-20 Poly1305;
 * persector_reference.py is independent. build_and_verify.sh diffs REF lines.
 * This is a MAC over existing ciphertext; the TAG STORAGE is a format change
 * ([FORMAT], out of scope for the no-header-change core) -- see the spec.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/chacha256.h"
#include "poly1305.h"

#define SECTOR 64
#define N      8

static void le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

static void sector_otk (const unsigned char smk[32], uint64_t index, unsigned char otk[32])
{
	ChaCha256Ctx c; unsigned char nonce[8], zero[32];
	le64 (index, nonce); memset (zero, 0, sizeof zero);
	ChaCha256Init (&c, smk, nonce, 20);
	ChaCha256Encrypt (&c, zero, 32, otk);
}

static void sector_tag (const unsigned char smk[32], uint64_t index,
                        const unsigned char *ct, size_t len, unsigned char tag[16])
{
	unsigned char otk[32];
	sector_otk (smk, index, otk);
	poly1305 (tag, ct, len, otk);
	memset (otk, 0, sizeof otk);
}

static int ct_eq16 (const unsigned char *a, const unsigned char *b)
{ unsigned char d = 0; int i; for (i = 0; i < 16; i++) d |= (unsigned char)(a[i] ^ b[i]); return d == 0; }

static int verify (const unsigned char smk[32], uint64_t index,
                   const unsigned char *ct, size_t len, const unsigned char tag[16])
{ unsigned char t[16]; sector_tag (smk, index, ct, len, t); return ct_eq16 (t, tag); }

static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

int main (void)
{
	unsigned char smk[32], ct[N][SECTOR], tags[N][16];
	int i, j;

	for (i = 0; i < 32; i++) smk[i] = (unsigned char) (0x40 + i);
	for (i = 0; i < N; i++)
		for (j = 0; j < SECTOR; j++)
			ct[i][j] = (unsigned char) ((i * 53 + j * 7 + 1) & 0xff);

	for (i = 0; i < N; i++) {
		sector_tag (smk, (uint64_t) i, ct[i], SECTOR, tags[i]);
		printf ("REF tag_%d ", i); hex (tags[i], 16); printf ("\n");
	}

	/* all sectors verify */
	{
		int ok = 1;
		for (i = 0; i < N; i++) if (!verify (smk, (uint64_t) i, ct[i], SECTOR, tags[i])) ok = 0;
		printf ("REF accept_all %s\n", ok ? "YES" : "NO");
	}

	/* tamper sector 5 -> only sector 5 fails */
	{
		unsigned char t5[SECTOR]; int fail5, others_ok = 1;
		memcpy (t5, ct[5], SECTOR); t5[0] ^= 0x01;
		fail5 = !verify (smk, 5, t5, SECTOR, tags[5]);
		for (i = 0; i < N; i++) if (i != 5 && !verify (smk, (uint64_t) i, ct[i], SECTOR, tags[i])) others_ok = 0;
		printf ("REF tamper_only_5_fails %s\n", (fail5 && others_ok) ? "YES" : "NO");
	}

	/* relocation: sector 3's (ciphertext, tag) presented at slot 5 and vice versa */
	{
		int reloc5 = verify (smk, 5, ct[3], SECTOR, tags[3]);
		int reloc3 = verify (smk, 3, ct[5], SECTOR, tags[5]);
		printf ("REF relocation_detected %s\n", (!reloc5 && !reloc3) ? "YES" : "NO");
	}

	/* wrong master key */
	{
		unsigned char wk[32]; memcpy (wk, smk, 32); wk[0] ^= 0x01;
		printf ("REF wrongkey_detected %s\n", !verify (wk, 0, ct[0], SECTOR, tags[0]) ? "YES" : "NO");
	}

	return 0;
}
