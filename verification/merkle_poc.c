/*
 * merkle_poc.c — proof-of-concept for a Merkle tree over the volume with the
 * root held off-disk (docs/MERKLE-SPEC.md, IDEAS-BACKLOG.md A). A binary hash
 * tree over sectors; a trusted off-disk root detects any offline tampering the
 * malleable XTS layer cannot. Each sector is verifiable in O(log N) via an
 * authentication path, so a single read needn't rehash the whole volume.
 *
 * Domain separation is RFC 6962 (Certificate Transparency):
 *     leaf(i,data) = SHA256(0x00 || le64(i) || data)   (index-bound)
 *     node(l,r)    = SHA256(0x01 || l || r)
 * Odd node counts promote the lone node unchanged (no duplicate-leaf ambiguity).
 *
 * This drives the REAL in-tree Crypto/Sha2.c; merkle_reference.py is independent
 * (hashlib). build_and_verify.sh diffs the REF lines byte-for-byte.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

#define DIGEST  32
#define N       8
#define SECTOR  64
#define MAXLVL  16   /* enough for 2^16 sectors */

static void le64 (uint64_t x, unsigned char out[8])
{ int i; for (i = 0; i < 8; i++) out[i] = (unsigned char) (x >> (8 * i)); }

static void leaf_hash (int index, const unsigned char *data, int len, unsigned char out[DIGEST])
{
	unsigned char tag = 0x00, ix[8];
	sha256_ctx c; sha256_begin (&c);
	le64 ((uint64_t) index, ix);
	sha256_hash (&tag, 1, &c);
	sha256_hash (ix, 8, &c);
	sha256_hash ((unsigned char *) data, (uint_32t) len, &c);
	sha256_end (out, &c);
}

static void node_hash (const unsigned char l[DIGEST], const unsigned char r[DIGEST], unsigned char out[DIGEST])
{
	unsigned char tag = 0x01;
	sha256_ctx c; sha256_begin (&c);
	sha256_hash (&tag, 1, &c);
	sha256_hash ((unsigned char *) l, DIGEST, &c);
	sha256_hash ((unsigned char *) r, DIGEST, &c);
	sha256_end (out, &c);
}

/* Build all levels bottom->top. levels[0]=leaves. Returns level count; fills
   counts[] and a flat store levels[lvl][k][DIGEST]. */
static int build_levels (const unsigned char sectors[N][SECTOR],
                         unsigned char levels[MAXLVL][N][DIGEST], int counts[MAXLVL])
{
	int nl = 0, i, cnt = N;
	for (i = 0; i < N; i++) leaf_hash (i, sectors[i], SECTOR, levels[0][i]);
	counts[0] = cnt; nl = 1;
	while (cnt > 1) {
		int j = 0, k = 0;
		while (j < cnt) {
			if (j + 1 < cnt) { node_hash (levels[nl-1][j], levels[nl-1][j+1], levels[nl][k]); j += 2; }
			else            { memcpy (levels[nl][k], levels[nl-1][j], DIGEST); j += 1; }
			k++;
		}
		counts[nl] = k; cnt = k; nl++;
	}
	return nl;
}

/* Authentication path for `index`: emit direction byte + sibling for each level
   that has a sibling. Returns byte length written to blob. */
static int auth_path (const unsigned char sectors[N][SECTOR], int index, unsigned char *blob)
{
	unsigned char levels[MAXLVL][N][DIGEST]; int counts[MAXLVL];
	int nl = build_levels (sectors, levels, counts);
	int idx = index, lvl, w = 0;
	for (lvl = 0; lvl < nl - 1; lvl++) {
		if (idx % 2 == 0) {
			if (idx + 1 < counts[lvl]) { blob[w++] = 0; memcpy (blob + w, levels[lvl][idx+1], DIGEST); w += DIGEST; }
		} else {
			blob[w++] = 1; memcpy (blob + w, levels[lvl][idx-1], DIGEST); w += DIGEST;
		}
		idx /= 2;
	}
	return w;
}

static int verify_path (int index, const unsigned char *data, int len,
                        const unsigned char *blob, int blen, const unsigned char root[DIGEST])
{
	unsigned char h[DIGEST]; int w = 0;
	leaf_hash (index, data, len, h);
	while (w < blen) {
		unsigned char dir = blob[w++]; const unsigned char *sib = blob + w; w += DIGEST;
		unsigned char t[DIGEST];
		if (dir == 0) node_hash (h, sib, t); else node_hash (sib, h, t);
		memcpy (h, t, DIGEST);
	}
	return memcmp (h, root, DIGEST) == 0;
}

static void compute_root (const unsigned char sectors[N][SECTOR], unsigned char root[DIGEST])
{
	unsigned char levels[MAXLVL][N][DIGEST]; int counts[MAXLVL];
	int nl = build_levels (sectors, levels, counts);
	memcpy (root, levels[nl-1][0], DIGEST);
}

static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

int main (void)
{
	unsigned char sectors[N][SECTOR], root[DIGEST];
	int i, j;
	for (i = 0; i < N; i++)
		for (j = 0; j < SECTOR; j++)
			sectors[i][j] = (unsigned char) ((i * 37 + j * 11 + 3) & 0xff);

	compute_root (sectors, root);
	printf ("REF root "); hex (root, DIGEST); printf ("\n");

	for (i = 0; i < N; i++) {
		unsigned char blob[MAXLVL * (1 + DIGEST)];
		int blen = auth_path (sectors, i, blob);
		int ok = verify_path (i, sectors[i], SECTOR, blob, blen, root);
		printf ("REF path_%d ", i); hex (blob, blen); printf ("\n");
		if (!ok) { fprintf (stderr, "path %d failed\n", i); return 1; }
	}

	/* tamper: flip one bit in sector 5 */
	{
		unsigned char tampered[N][SECTOR], root2[DIGEST], blob[MAXLVL * (1 + DIGEST)];
		int blen, rejected;
		memcpy (tampered, sectors, sizeof tampered);
		tampered[5][0] ^= 0x01;
		compute_root (tampered, root2);
		printf ("REF tamper_root "); hex (root2, DIGEST); printf ("\n");
		printf ("REF tamper_detected %s\n", memcmp (root2, root, DIGEST) != 0 ? "YES" : "NO");
		/* sector-5 auth path (from the untampered tree) must reject the tampered data vs the trusted root */
		blen = auth_path (sectors, 5, blob);
		rejected = !verify_path (5, tampered[5], SECTOR, blob, blen, root);
		printf ("REF tamper_path_rejected %s\n", rejected ? "YES" : "NO");
		if (memcmp (root2, root, DIGEST) == 0 || !rejected) return 1;
	}
	return 0;
}
