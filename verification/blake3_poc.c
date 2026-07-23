/*
 * blake3_poc.c — BLAKE3 tree hash (docs/HASHES-SPEC.md, IDEAS-BACKLOG.md
 * "Hashes" row). BLAKE3 (O'Connor, Aumasson, Neves, Wilcox-O'Hearn, 2020):
 * 7-round BLAKE2s-style compression, 1024-byte chunks, binary tree with
 * power-of-two left subtrees, built-in keyed-hash and derive-key modes, and
 * arbitrary-length XOF output. Candidate as a fast keyfile/pool hash and as
 * the tree hash for the Merkle integrity work (its chunk tree IS a Merkle
 * tree with a keyed root).
 *
 * BLAKE3 is NOT in the VeraCrypt tree, so (like Poly1305, step [18]) the proof
 * is: (1) the official published test vectors — blake3_kats.h, all 35 cases
 * (0..102400 bytes, hash + keyed_hash + derive_key, 131-byte XOF each) — and
 * (2) byte-identical REF output against the independent blake3_reference.py.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "blake3_kats.h"

#define CHUNK_START 1
#define CHUNK_END   2
#define PARENT      4
#define ROOT        8
#define KEYED_HASH  16
#define DERIVE_KEY_CONTEXT  32
#define DERIVE_KEY_MATERIAL 64

static const uint32_t IV[8] = {
	0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
	0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u };
static const unsigned char PERM[16] = {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};

static uint32_t ror32 (uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void g (uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y)
{
	v[a] += v[b] + x; v[d] = ror32 (v[d] ^ v[a], 16);
	v[c] += v[d];     v[b] = ror32 (v[b] ^ v[c], 12);
	v[a] += v[b] + y; v[d] = ror32 (v[d] ^ v[a], 8);
	v[c] += v[d];     v[b] = ror32 (v[b] ^ v[c], 7);
}

static void compress (const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
                      uint32_t blen, uint32_t flags, uint32_t out16[16])
{
	uint32_t v[16], m[16], t[16];
	int r, i;
	memcpy (v, cv, 32); memcpy (v + 8, IV, 16);
	v[12] = (uint32_t) counter; v[13] = (uint32_t)(counter >> 32);
	v[14] = blen; v[15] = flags;
	memcpy (m, block, 64);
	for (r = 0; r < 7; r++) {
		g (v, 0, 4, 8, 12, m[0], m[1]);  g (v, 1, 5, 9, 13, m[2], m[3]);
		g (v, 2, 6, 10, 14, m[4], m[5]); g (v, 3, 7, 11, 15, m[6], m[7]);
		g (v, 0, 5, 10, 15, m[8], m[9]); g (v, 1, 6, 11, 12, m[10], m[11]);
		g (v, 2, 7, 8, 13, m[12], m[13]); g (v, 3, 4, 9, 14, m[14], m[15]);
		if (r < 6) { for (i = 0; i < 16; i++) t[i] = m[PERM[i]]; memcpy (m, t, 64); }
	}
	for (i = 0; i < 8; i++) { out16[i] = v[i] ^ v[i + 8]; out16[i + 8] = v[i + 8] ^ cv[i]; }
}

static void load_block (const unsigned char *p, size_t n, uint32_t w[16])
{
	unsigned char buf[64]; int i;
	memset (buf, 0, 64); memcpy (buf, p, n);
	for (i = 0; i < 16; i++)
		w[i] = (uint32_t) buf[4*i] | ((uint32_t) buf[4*i+1] << 8)
		     | ((uint32_t) buf[4*i+2] << 16) | ((uint32_t) buf[4*i+3] << 24);
}

/* output node: the (cv, block, blen, flags) whose ROOT-flagged re-compressions
   with counter 0,1,2,.. produce the extended output */
typedef struct { uint32_t cv[8], block[16], blen, flags; } Output;

static void out_root (const Output *o, unsigned char *dst, size_t n)
{
	uint32_t w[16]; unsigned char blk[64];
	uint64_t t = 0; size_t off = 0, c; int i;
	while (off < n) {
		compress (o->cv, o->block, t++, o->blen, o->flags | ROOT, w);
		for (i = 0; i < 16; i++) { blk[4*i] = (unsigned char) w[i]; blk[4*i+1] = (unsigned char)(w[i]>>8); blk[4*i+2] = (unsigned char)(w[i]>>16); blk[4*i+3] = (unsigned char)(w[i]>>24); }
		c = n - off < 64 ? n - off : 64;
		memcpy (dst + off, blk, c); off += c;
	}
}

static void out_chain (const Output *o, uint64_t counter, uint32_t cv[8])
{
	uint32_t w[16];
	compress (o->cv, o->block, counter, o->blen, o->flags, w);
	memcpy (cv, w, 32);
}

/* process one chunk into its output node */
static void chunk_output (const uint32_t key[8], const unsigned char *p, size_t n,
                          uint64_t index, uint32_t base, Output *o)
{
	uint32_t cv[8], w[16];
	size_t nb = n ? (n + 63) / 64 : 1, i;
	memcpy (cv, key, 32);
	for (i = 0; i < nb; i++) {
		size_t blen = (i == nb - 1) ? n - 64 * i : 64;
		uint32_t flags = base | (i == 0 ? CHUNK_START : 0) | (i == nb - 1 ? CHUNK_END : 0);
		load_block (p + 64 * i, blen, w);
		if (i == nb - 1) {
			memcpy (o->cv, cv, 32); memcpy (o->block, w, 64);
			o->blen = (uint32_t) blen; o->flags = flags;
			return;
		}
		compress (cv, w, index, 64, flags, w);   /* w reused: first 8 words are the cv */
		memcpy (cv, w, 32);
	}
}

static size_t left_len (size_t nchunks)
{
	size_t p = 1;
	while (p * 2 < nchunks) p *= 2;   /* largest power of two <= nchunks-1 */
	return p;
}

static void subtree_cv (const uint32_t key[8], const unsigned char *p, size_t n,
                        uint64_t first_index, uint32_t base, uint32_t cv[8])
{
	size_t nchunks = n ? (n + 1023) / 1024 : 1;
	if (nchunks == 1) {
		Output o;
		chunk_output (key, p, n, first_index, base, &o);
		out_chain (&o, first_index, cv);
		return;
	}
	{
		size_t l = left_len (nchunks);
		uint32_t lcv[8], rcv[8], blk[16];
		Output o;
		subtree_cv (key, p, l * 1024, first_index, base, lcv);
		subtree_cv (key, p + l * 1024, n - l * 1024, first_index + l, base, rcv);
		memcpy (blk, lcv, 32); memcpy (blk + 8, rcv, 32);
		memcpy (o.cv, key, 32); memcpy (o.block, blk, 64); o.blen = 64; o.flags = base | PARENT;
		out_chain (&o, 0, cv);
	}
}

static void blake3 (const unsigned char *p, size_t n, const uint32_t key[8], uint32_t base,
                    unsigned char *dst, size_t out_len)
{
	size_t nchunks = n ? (n + 1023) / 1024 : 1;
	Output o;
	if (nchunks == 1) {
		chunk_output (key, p, n, 0, base, &o);
	} else {
		size_t l = left_len (nchunks);
		uint32_t lcv[8], rcv[8];
		subtree_cv (key, p, l * 1024, 0, base, lcv);
		subtree_cv (key, p + l * 1024, n - l * 1024, l, base, rcv);
		memcpy (o.cv, key, 32); memcpy (o.block, lcv, 32); memcpy (o.block + 8, rcv, 32);
		o.blen = 64; o.flags = base | PARENT;
	}
	out_root (&o, dst, out_len);
}

static void key_words (const unsigned char k[32], uint32_t w[8])
{
	int i;
	for (i = 0; i < 8; i++)
		w[i] = (uint32_t) k[4*i] | ((uint32_t) k[4*i+1] << 8)
		     | ((uint32_t) k[4*i+2] << 16) | ((uint32_t) k[4*i+3] << 24);
}

static void hex (const unsigned char *b, size_t n) { size_t i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

#define OUTLEN 131
static unsigned char pattern[102400];

#ifndef BLAKE3_NO_MAIN   /* persector_poc.c includes this file to reuse the proven keyed BLAKE3 and
                            supplies its own main; step [27] leaves it defined */
int main (void)
{
	unsigned char out[OUTLEN], expect[OUTLEN];
	uint32_t kw[8], ckw[8];
	unsigned char ck[32];
	size_t i;
	int c, all = 1;

	for (i = 0; i < sizeof pattern; i++) pattern[i] = (unsigned char)(i % 251);
	key_words ((const unsigned char *) BLAKE3_KAT_KEY, kw);
	/* derive-key context key: blake3(context, IV, DERIVE_KEY_CONTEXT) -> 32 bytes */
	blake3 ((const unsigned char *) BLAKE3_KAT_CONTEXT, strlen (BLAKE3_KAT_CONTEXT),
	        IV, DERIVE_KEY_CONTEXT, ck, 32);
	key_words (ck, ckw);

	for (c = 0; c < BLAKE3_NKATS; c++) {
		size_t n = blake3_kats[c].input_len, j;
		const char *exp3[3] = { blake3_kats[c].hash, blake3_kats[c].keyed, blake3_kats[c].derive };
		static const char *tag[3] = { "hash", "keyed", "derive" };
		for (j = 0; j < 3; j++) {
			size_t k2;
			if (j == 0) blake3 (pattern, n, IV, 0, out, OUTLEN);
			else if (j == 1) blake3 (pattern, n, kw, KEYED_HASH, out, OUTLEN);
			else blake3 (pattern, n, ckw, DERIVE_KEY_MATERIAL, out, OUTLEN);
			printf ("REF %s_%u ", tag[j], (unsigned) n); hex (out, OUTLEN); printf ("\n");
			for (k2 = 0; k2 < OUTLEN; k2++) {
				unsigned v; sscanf (exp3[j] + 2 * k2, "%2x", &v); expect[k2] = (unsigned char) v;
			}
			if (memcmp (out, expect, OUTLEN) != 0) all = 0;
		}
	}
	printf ("REF all_match %s\n", all ? "YES" : "NO");
	return all ? 0 : 1;
}
#endif /* BLAKE3_NO_MAIN */
