/*
 * v2format_poc.c — v2 on-disk format, the two NOVEL format-level properties (T1-1).
 *
 * The v2 format (docs/V2-FORMAT-SPEC.md) composes already-proven primitives — HCTR2 (step [26]),
 * Adiantum (step [24]), keyed-BLAKE3 per-sector auth (step [21]), HKF mix v2 (step [80]) — under three
 * owner decisions: (1) store NO wide-block mode selector, derive/trial it at mount; (2) trial-derivation
 * for v1/v2 detection; (3) a full-volume per-sector MAC table (free slots = keystream). This harness
 * proves the two things that are NEW at the format level, not the ciphers themselves:
 *
 *   A. MODE DISCRIMINATION WITH NOTHING STORED. The per-sector tag is over CIPHERTEXT (encrypt-then-MAC),
 *      so the tag alone cannot tell HCTR2 from Adiantum — the ciphertext bytes are identical either way.
 *      Discrimination comes from a per-mode DOMAIN-SEPARATED MAC key:
 *         K_mac[mode] = keyed-BLAKE3(master, "VeraCrypt/v2/mac/" || mode)
 *         tag_i       = keyed-BLAKE3(K_mac[mode], le64(i) || ct_i)[0..16]
 *      At mount, sector 0's tag is recomputed under each mode's key; exactly one reproduces it. That
 *      identifies the mode with no stored selector, keeps AE order, and binds the mode (anti-downgrade).
 *
 *   B. FULL-VOLUME MAC TABLE INDISTINGUISHABILITY. Written sectors hold a real tag; never-written sectors
 *      hold keystream. Both are pseudorandom, so the table leaks nothing about which sectors are used;
 *      a hidden volume overwriting the outer's free region still reads as "free" (MAC mismatch) from the
 *      outer's view — the SAME view v1 gives of random free space, so no new tell. v2 gives integrity
 *      for ALLOCATED data, not free space — which is exactly what preserves hidden-volume deniability.
 *
 * Uses the REAL proven keyed BLAKE3 by including blake3_poc.c (BLAKE3_NO_MAIN) — same technique as
 * persector_poc.c — for the MAC, the per-mode KDF, and the keystream PRG. The wide-block ciphers
 * themselves are proven in steps [24]/[26]; here a mode's data is modelled by keyed-BLAKE3 keystream so
 * the property under test is purely the format composition. v2format_reference.py recomputes every
 * printed REF line independently; the suite diffs them byte-for-byte.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define BLAKE3_NO_MAIN
#include "blake3_poc.c"   /* real keyed BLAKE3: blake3(), key_words(), KEYED_HASH, hex() */

#define TAGLEN 16
#define SECTOR 64
#define NSEC   512        /* full-volume table: enough bytes (NSEC*TAGLEN = 8192) for a real chi-square */
#define NWRIT  128        /* written sectors; the rest are free (keystream slots) */

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-52s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }

static void le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

/* keyed BLAKE3 as a PRF: out = keyed-BLAKE3(key, in)[0..outlen] */
static void kbl (const unsigned char key[32], const unsigned char *in, size_t n,
                 unsigned char *out, size_t outlen)
{ uint32_t kw[8]; key_words (key, kw); blake3 (in, n, kw, KEYED_HASH, out, outlen); }

/* KDF: subkey = keyed-BLAKE3(master, label) — domain separation by ASCII label */
static void kdf (const unsigned char master[32], const char *label, unsigned char *out, size_t outlen)
{ kbl (master, (const unsigned char *) label, strlen (label), out, outlen); }

/* PRG: out = keyed-BLAKE3(key, le64(counter))[0..outlen] — a real keystream */
static void prg (const unsigned char key[32], uint64_t counter, unsigned char *out, size_t outlen)
{ unsigned char c[8]; le64 (counter, c); kbl (key, c, 8, out, outlen); }

/* tag_i = keyed-BLAKE3(K_mac, le64(index) || ciphertext)[0..TAGLEN] (encrypt-then-MAC, index-bound) */
static void sector_tag (const unsigned char kmac[32], uint64_t index,
                        const unsigned char *ct, size_t len, unsigned char tag[TAGLEN])
{ unsigned char in[8 + SECTOR]; le64 (index, in); memcpy (in + 8, ct, len); kbl (kmac, in, 8 + len, tag, TAGLEN); }

static int ct_eq (const unsigned char *a, const unsigned char *b, int n)
{ unsigned char d = 0; int i; for (i = 0; i < n; i++) d |= (unsigned char)(a[i] ^ b[i]); return d == 0; }

static int verify (const unsigned char kmac[32], uint64_t index,
                   const unsigned char *ct, size_t len, const unsigned char tag[TAGLEN])
{ unsigned char t[TAGLEN]; sector_tag (kmac, index, ct, len, t); return ct_eq (t, tag, TAGLEN); }

int main (void)
{
	unsigned char master[32];
	unsigned char kmac_h[32], kmac_a[32], kenc_h[32], kfree[32], kfreedata[32], khidden[32];
	unsigned char ct0[SECTOR], tag0[TAGLEN], t_under_a[TAGLEN];
	int i;

	for (i = 0; i < 32; i++) master[i] = (unsigned char) ((0x40 + i) & 0xff);

	/* per-mode domain-separated keys (decision 1 + 3) */
	kdf (master, "VeraCrypt/v2/mac/hctr2",     kmac_h,   32);
	kdf (master, "VeraCrypt/v2/mac/adiantum",  kmac_a,   32);
	kdf (master, "VeraCrypt/v2/enc/hctr2",     kenc_h,   32);
	kdf (master, "VeraCrypt/v2/tablefree",     kfree,    32);
	kdf (master, "VeraCrypt/v2/freedata",      kfreedata,32);
	kdf (master, "VeraCrypt/v2/hidden",        khidden,  32);

	printf ("[A] mode discrimination with nothing stored (per-mode MAC key over ciphertext)\n");
	prg (kenc_h, 0, ct0, SECTOR);                 /* sector 0 written under the hctr2-mode key */
	sector_tag (kmac_h, 0, ct0, SECTOR, tag0);    /* tag under K_mac[hctr2] */
	printf ("REF kmac_hctr2 "); hex (kmac_h, 32); printf ("\n");
	printf ("REF tag0 ");       hex (tag0, TAGLEN); printf ("\n");
	{
		int as_h = verify (kmac_h, 0, ct0, SECTOR, tag0);   /* recompute under hctr2 key -> matches */
		int as_a = verify (kmac_a, 0, ct0, SECTOR, tag0);   /* under adiantum key -> must differ */
		sector_tag (kmac_a, 0, ct0, SECTOR, t_under_a);
		printf ("REF discriminate %s\n", (as_h && !as_a) ? "YES" : "NO");
		check ("mode identified by which K_mac reproduces the tag", as_h && !as_a);
		check ("tag differs under the wrong mode key (anti-downgrade binding)",
		       !ct_eq (tag0, t_under_a, TAGLEN));
	}
	{
		/* v1 fallthrough: a legacy volume has no v2 tag; the bytes where a tag WOULD be are just data.
		   Neither v2 mode key verifies -> mount falls through to v1. */
		unsigned char v1slot[TAGLEN];
		prg (kenc_h, 0xdead, v1slot, TAGLEN);       /* arbitrary non-tag bytes */
		int v_h = verify (kmac_h, 0, ct0, SECTOR, v1slot);
		int v_a = verify (kmac_a, 0, ct0, SECTOR, v1slot);
		printf ("REF v1_fallthrough %s\n", (!v_h && !v_a) ? "YES" : "NO");
		check ("no v2 mode verifies a legacy sector -> falls through to v1", !v_h && !v_a);
	}

	printf ("[B] full-volume MAC table indistinguishability (free slots = keystream)\n");
	{
		static unsigned char table[NSEC][TAGLEN];
		static unsigned char written_ct[NWRIT][SECTOR];
		unsigned char tblhash[32];
		long hist[256]; long total = 0; double chisq = 0.0, expv; int b;
		int written_ok = 1, free_reads_free = 1, hidden_reads_free = 1;

		for (i = 0; i < NSEC; i++) {
			if (i < NWRIT) {                                   /* written sector -> real tag */
				prg (kenc_h, (uint64_t) (1000 + i), written_ct[i], SECTOR);
				sector_tag (kmac_h, (uint64_t) i, written_ct[i], SECTOR, table[i]);
			} else {                                           /* never-written -> keystream fill */
				prg (kfree, (uint64_t) i, table[i], TAGLEN);
			}
		}
		/* anchor: hash of the whole table */
		kbl (master, (const unsigned char *) table, sizeof table, tblhash, 32);
		printf ("REF table_hash "); hex (tblhash, 32); printf ("\n");

		/* (B1) integrity for allocated data: every written sector verifies */
		for (i = 0; i < NWRIT; i++)
			if (!verify (kmac_h, (uint64_t) i, written_ct[i], SECTOR, table[i])) written_ok = 0;
		printf ("REF written_verify %s\n", written_ok ? "YES" : "NO");
		check ("integrity holds for allocated (written) data", written_ok);

		/* (B2) a free slot reads as FREE, not tamper: the keystream slot does not verify as a MAC over
		   whatever random bytes actually sit in that free sector on disk. */
		for (i = NWRIT; i < NSEC; i++) {
			unsigned char freebytes[SECTOR];
			prg (kfreedata, (uint64_t) i, freebytes, SECTOR);   /* random on-disk free content */
			if (verify (kmac_h, (uint64_t) i, freebytes, SECTOR, table[i])) free_reads_free = 0;
		}
		printf ("REF free_reads_as_free %s\n", free_reads_free ? "YES" : "NO");
		check ("free-slot keystream never verifies -> read as free, not tamper", free_reads_free);

		/* (B3) hidden-overwrite: a hidden volume writes its own ciphertext into the outer's free region;
		   the outer's table slot (keystream) is unchanged, so the outer still reads those sectors as free
		   -> the hidden volume is indistinguishable from free space to the outer. */
		for (i = NWRIT; i < NSEC; i++) {
			unsigned char hct[SECTOR];
			prg (khidden, (uint64_t) i, hct, SECTOR);           /* hidden volume's ciphertext */
			if (verify (kmac_h, (uint64_t) i, hct, SECTOR, table[i])) hidden_reads_free = 0;
		}
		printf ("REF hidden_reads_as_free %s\n", hidden_reads_free ? "YES" : "NO");
		check ("hidden-volume overwrite of free region still reads as free (no new tell)", hidden_reads_free);

		/* (B4) byte-uniformity of the whole table (real tags UNION keystream) — a chi-square over 256
		   bins. Deterministic inputs => a fixed statistic; assert it is in the uniform range. */
		for (b = 0; b < 256; b++) hist[b] = 0;
		for (i = 0; i < NSEC; i++) { int j; for (j = 0; j < TAGLEN; j++) { hist[table[i][j]]++; total++; } }
		expv = (double) total / 256.0;
		for (b = 0; b < 256; b++) { double d = (double) hist[b] - expv; chisq += d * d / expv; }
		printf ("REF table_chisq %ld\n", (long) (chisq + 0.5));   /* integer for exact C/python match */
		/* 255 dof: expected ~255, p=0.001 critical ~330. A generous bound keeps it a real but non-flaky
		   uniformity gate (the value is deterministic given the fixed inputs). */
		check ("table bytes are uniform (real tags indistinguishable from free keystream)",
		       (long) (chisq + 0.5) < 360);
	}

	printf ("\n%s\n", all_pass
	        ? "V2 FORMAT POC PASSED (mode discrimination w/ nothing stored; full-volume MAC-table indistinguishability)"
	        : "V2 FORMAT POC FAILED");
	return all_pass ? 0 : 1;
}
