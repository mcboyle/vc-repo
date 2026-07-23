/*
 * persector_poc.c — per-sector authentication (docs/PERSECTOR-AUTH-SPEC.md,
 * IDEAS-BACKLOG.md A). dm-integrity-style tamper detection: one MAC tag per
 * sector, stored in a separate tag area, computed over the sector CIPHERTEXT
 * (encrypt-then-MAC) and BOUND to the sector index.
 *
 *   tag_i = keyed_BLAKE3(K_mac, le64(sector_index) || ciphertext_i)[0..16]   # 128-bit tag
 *
 * PRF, not a one-time MAC (research batch-2 item C2). The prior construction was
 *   otk_i = ChaCha20(sector_mac_key, le64(index))[0..32];  tag_i = Poly1305(otk_i, ct_i)
 * which reused the SAME one-time Poly1305 key on every REWRITE of a sector (otk_i is a pure
 * function of the index, not the content). Poly1305 is a one-time Wegman-Carter MAC: two tag
 * versions of one sector (exactly what a multi-snapshot / stale-FTL-page adversary holds) recover
 * (r,s) and let the sector be forged forever. A PRF (keyed BLAKE3) degrades gracefully under key
 * reuse — two rewrites of a sector yield independent tags with no key recovery — and is naturally
 * constant-time. Chose keyed BLAKE3 (already proven in step [27]) over the KMAC256 fallback to reuse
 * an in-tree-proven primitive with no new dependency; KMAC256 would be the conservative alternative.
 *
 * Design points KEPT from the original: le64(sector_index) stays INSIDE the PRF input, so a valid tag
 * copied to another sector fails (relocation resistance). K_mac is domain-separated from the
 * encryption key (here the test's sector_mac_key). Encrypt-then-MAC, verify before decrypt.
 *
 * Reuses the REAL proven BLAKE3 by including blake3_poc.c (BLAKE3_NO_MAIN) — same technique
 * shamir_dudect_test.c uses to include Shamir.c; do NOT write a second BLAKE3.
 * persector_reference.py is independent. build_and_verify.sh diffs REF lines.
 * The TAG STORAGE is a format change ([FORMAT], out of scope for the no-header-change core) — see the spec.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define BLAKE3_NO_MAIN
#include "blake3_poc.c"   /* real keyed BLAKE3: blake3(), key_words(), KEYED_HASH, hex() */

#define SECTOR  64
#define N       8
#define TAGLEN  16

static void le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

/* tag_i = keyed_BLAKE3(K_mac, le64(index) || ciphertext)[0..TAGLEN] */
static void sector_tag (const unsigned char kmac[32], uint64_t index,
                        const unsigned char *ct, size_t len, unsigned char tag[TAGLEN])
{
	unsigned char in[8 + SECTOR];
	uint32_t kw[8];
	le64 (index, in);
	memcpy (in + 8, ct, len);
	key_words (kmac, kw);
	blake3 (in, 8 + len, kw, KEYED_HASH, tag, TAGLEN);
	memset (kw, 0, sizeof kw);        /* burn the key words derived from K_mac */
	memset (in, 0, sizeof in);
}

static int ct_eq16 (const unsigned char *a, const unsigned char *b)
{ unsigned char d = 0; int i; for (i = 0; i < TAGLEN; i++) d |= (unsigned char)(a[i] ^ b[i]); return d == 0; }

static int verify (const unsigned char kmac[32], uint64_t index,
                   const unsigned char *ct, size_t len, const unsigned char tag[TAGLEN])
{ unsigned char t[TAGLEN]; sector_tag (kmac, index, ct, len, t); return ct_eq16 (t, tag); }

int main (void)
{
	unsigned char kmac[32], ct[N][SECTOR], tags[N][TAGLEN];
	int i, j;

	for (i = 0; i < 32; i++) kmac[i] = (unsigned char) (0x40 + i);
	for (i = 0; i < N; i++)
		for (j = 0; j < SECTOR; j++)
			ct[i][j] = (unsigned char) ((i * 53 + j * 7 + 1) & 0xff);

	for (i = 0; i < N; i++) {
		sector_tag (kmac, (uint64_t) i, ct[i], SECTOR, tags[i]);
		printf ("REF tag_%d ", i); hex (tags[i], TAGLEN); printf ("\n");
	}

	/* (1) all sectors verify */
	{
		int ok = 1;
		for (i = 0; i < N; i++) if (!verify (kmac, (uint64_t) i, ct[i], SECTOR, tags[i])) ok = 0;
		printf ("REF accept_all %s\n", ok ? "YES" : "NO");
	}

	/* (2) per-sector independence: tamper sector 5 -> only sector 5 fails */
	{
		unsigned char t5[SECTOR]; int fail5, others_ok = 1;
		memcpy (t5, ct[5], SECTOR); t5[0] ^= 0x01;
		fail5 = !verify (kmac, 5, t5, SECTOR, tags[5]);
		for (i = 0; i < N; i++) if (i != 5 && !verify (kmac, (uint64_t) i, ct[i], SECTOR, tags[i])) others_ok = 0;
		printf ("REF tamper_only_5_fails %s\n", (fail5 && others_ok) ? "YES" : "NO");
	}

	/* (3) relocation: sector 3's (ciphertext, tag) presented at slot 5 and vice versa -> rejected
	   (le64(index) inside the PRF input binds the tag to its sector) */
	{
		int reloc5 = verify (kmac, 5, ct[3], SECTOR, tags[3]);
		int reloc3 = verify (kmac, 3, ct[5], SECTOR, tags[5]);
		printf ("REF relocation_detected %s\n", (!reloc5 && !reloc3) ? "YES" : "NO");
	}

	/* (4) wrong master key -> tag differs */
	{
		unsigned char wk[32]; memcpy (wk, kmac, 32); wk[0] ^= 0x01;
		printf ("REF wrongkey_detected %s\n", !verify (wk, 0, ct[0], SECTOR, tags[0]) ? "YES" : "NO");
	}

	/* (5) NEW — rewrite/key-reuse safety (the property the one-time Poly1305 construction FAILED):
	   two rewrites of the SAME sector under the SAME K_mac (new content each time) produce INDEPENDENT
	   tags. With a PRF there is no (r,s) one-time key to recover from the pair; both tags verify only
	   against their own content, and neither forges the other. We assert: the two tags differ, each
	   verifies its own content, and each is rejected against the other's content. */
	{
		unsigned char v1[SECTOR], v2[SECTOR], tg1[TAGLEN], tg2[TAGLEN];
		int diff, v1ok, v2ok, cross1, cross2;
		for (j = 0; j < SECTOR; j++) v1[j] = (unsigned char) ((j * 3 + 11) & 0xff);      /* rewrite #1 */
		for (j = 0; j < SECTOR; j++) v2[j] = (unsigned char) ((j * 5 + 200) & 0xff);     /* rewrite #2 */
		sector_tag (kmac, 5, v1, SECTOR, tg1);
		sector_tag (kmac, 5, v2, SECTOR, tg2);
		diff   = !ct_eq16 (tg1, tg2);
		v1ok   =  verify (kmac, 5, v1, SECTOR, tg1);
		v2ok   =  verify (kmac, 5, v2, SECTOR, tg2);
		cross1 = !verify (kmac, 5, v2, SECTOR, tg1);   /* tag1 must NOT authenticate content 2 */
		cross2 = !verify (kmac, 5, v1, SECTOR, tg2);   /* tag2 must NOT authenticate content 1 */
		printf ("REF rewrite_reuse_safe %s\n",
		        (diff && v1ok && v2ok && cross1 && cross2) ? "YES" : "NO");
	}

	return 0;
}
