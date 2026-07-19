/*
 * threefish_poc.c — Threefish large-block cipher (docs/LARGE-BLOCK-SPEC.md,
 * IDEAS-BACKLOG.md "Large-block ciphers" row). Threefish is the tweakable block
 * cipher inside Skein; its 1024-bit block gives ~2^64x the birthday-bound
 * headroom of AES's 128-bit block — relevant for very large volumes. Compact
 * canonical algorithm (Skein 1.3 spec) for both 512- and 1024-bit blocks.
 *
 * NOT in the VeraCrypt tree. Proof: Threefish-512 against the OFFICIAL Botan
 * published vectors (threefish_kats.h) — the independent authority pinning down
 * the MIX/rotation/key-schedule/permute machinery — plus byte-identical REF
 * output against threefish_reference.py (independent python) and encrypt/decrypt
 * round-trip for both block sizes.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "threefish_kats.h"

#define C240 0x1BD11BDAA9FC1A22ULL

static const int ROT512[8][4] = {
	{46,36,19,37},{33,27,14,42},{17,49,36,39},{44,9,54,56},
	{39,30,34,24},{13,50,10,17},{25,29,39,43},{8,35,56,22} };
static const int PERM512[8] = {2,1,4,7,6,5,0,3};

static const int ROT1024[8][8] = {
	{24,13,8,47,8,17,22,37},{38,19,10,55,49,18,23,52},
	{33,4,51,13,34,41,59,17},{5,20,48,41,47,28,16,25},
	{41,9,37,31,12,47,44,30},{16,34,56,51,4,53,42,41},
	{31,44,47,46,19,42,44,25},{9,48,35,52,23,31,37,20} };
static const int PERM1024[16] = {0,9,2,13,6,11,4,15,10,7,12,3,14,5,8,1};

static uint64_t rotl (uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

/* subkey schedule: ks[nsub][nw]; nw in {8,16} */
static void key_schedule (const uint64_t *kwords, const uint64_t tw[2], int nw, uint64_t ks[21][16])
{
	uint64_t k[17], t[3];
	int nrounds = (nw == 8) ? 72 : 80, nsub = nrounds / 4 + 1, s, i;
	for (i = 0; i < nw; i++) k[i] = kwords[i];
	k[nw] = C240;
	for (i = 0; i < nw; i++) k[nw] ^= kwords[i];
	t[0] = tw[0]; t[1] = tw[1]; t[2] = tw[0] ^ tw[1];
	for (s = 0; s < nsub; s++) {
		for (i = 0; i < nw; i++) ks[s][i] = k[(s + i) % (nw + 1)];
		ks[s][nw - 3] += t[s % 3];
		ks[s][nw - 2] += t[(s + 1) % 3];
		ks[s][nw - 1] += (uint64_t) s;
	}
}

static void encrypt_block (const uint64_t *kw, const uint64_t tw[2], int nw, const uint64_t *in, uint64_t *out)
{
	uint64_t ks[21][16], v[16], nvv[16];
	int nrounds = (nw == 8) ? 72 : 80, d, i;
	const int (*rot)[8] = NULL; const int (*rot4)[4] = NULL; const int *perm;
	if (nw == 8) { rot4 = ROT512; perm = PERM512; } else { rot = ROT1024; perm = PERM1024; }
	key_schedule (kw, tw, nw, ks);
	for (i = 0; i < nw; i++) v[i] = in[i];
	for (d = 0; d < nrounds; d++) {
		if (d % 4 == 0) for (i = 0; i < nw; i++) v[i] += ks[d / 4][i];
		for (i = 0; i < nw / 2; i++) {
			uint64_t x0 = v[2*i], x1 = v[2*i+1], y0 = x0 + x1;
			int r = (nw == 8) ? rot4[d % 8][i] : rot[d % 8][i];
			nvv[2*i] = y0; nvv[2*i+1] = rotl (x1, r) ^ y0;
		}
		for (i = 0; i < nw; i++) v[i] = nvv[perm[i]];
	}
	for (i = 0; i < nw; i++) out[i] = v[i] + ks[nrounds / 4][i];
}

static void decrypt_block (const uint64_t *kw, const uint64_t tw[2], int nw, const uint64_t *in, uint64_t *out)
{
	uint64_t ks[21][16], v[16], pv[16];
	int nrounds = (nw == 8) ? 72 : 80, d, i, inv[16];
	const int (*rot)[8] = NULL; const int (*rot4)[4] = NULL; const int *perm;
	if (nw == 8) { rot4 = ROT512; perm = PERM512; } else { rot = ROT1024; perm = PERM1024; }
	key_schedule (kw, tw, nw, ks);
	for (i = 0; i < nw; i++) inv[perm[i]] = i;
	for (i = 0; i < nw; i++) v[i] = in[i] - ks[nrounds / 4][i];
	for (d = nrounds - 1; d >= 0; d--) {
		for (i = 0; i < nw; i++) pv[i] = v[inv[i]];
		for (i = 0; i < nw / 2; i++) {
			uint64_t y0 = pv[2*i], y1 = pv[2*i+1], x1;
			int r = (nw == 8) ? rot4[d % 8][i] : rot[d % 8][i];
			x1 = rotl (y1 ^ y0, 64 - r);
			v[2*i] = y0 - x1; v[2*i+1] = x1;
		}
		if (d % 4 == 0) for (i = 0; i < nw; i++) v[i] -= ks[d / 4][i];
	}
	for (i = 0; i < nw; i++) out[i] = v[i];
}

static int hexval (char c)
{ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c - 'A' + 10; }
static size_t unhex (const char *s, unsigned char *o)
{ size_t n = strlen (s) / 2, i; for (i = 0; i < n; i++) o[i] = (unsigned char)((hexval (s[2*i])<<4)|hexval (s[2*i+1])); return n; }
static void towords (const unsigned char *b, int nbytes, uint64_t *w)
{ int i, j; for (i = 0; i < nbytes / 8; i++) { w[i] = 0; for (j = 0; j < 8; j++) w[i] |= (uint64_t) b[8*i+j] << (8*j); } }
static void frombytes (const uint64_t *w, int nw, unsigned char *b)
{ int i, j; for (i = 0; i < nw; i++) for (j = 0; j < 8; j++) b[8*i+j] = (unsigned char)(w[i] >> (8*j)); }
static void hex (const unsigned char *b, int n) { int i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

int main (void)
{
	unsigned char kb[128], tb[16], pb[128], cb[128], ob[128];
	uint64_t kw[16], tw[2], iw[16], ow[16];
	int i, all = 1;

	/* Threefish-512 vs official Botan vectors */
	for (i = 0; i < TF512_NKATS; i++) {
		unhex (tf512_kats[i][0], kb); unhex (tf512_kats[i][1], tb);
		unhex (tf512_kats[i][2], pb); unhex (tf512_kats[i][3], cb);
		towords (kb, 64, kw); towords (tb, 16, tw); towords (pb, 64, iw);
		encrypt_block (kw, tw, 8, iw, ow); frombytes (ow, 8, ob);
		printf ("REF tf512_%d ", i); hex (ob, 64); printf ("\n");
		if (memcmp (ob, cb, 64) != 0) all = 0;
	}
	printf ("REF tf512_official_match %s\n", all ? "YES" : "NO");

	/* Threefish-1024 deterministic vector (matches threefish_reference.py) */
	for (i = 0; i < 128; i++) kb[i] = (unsigned char) i;
	for (i = 0; i < 16; i++)  tb[i] = (unsigned char)(0x10 + i);
	for (i = 0; i < 128; i++) pb[i] = (unsigned char)(0xff - i);
	towords (kb, 128, kw); towords (tb, 16, tw); towords (pb, 128, iw);
	encrypt_block (kw, tw, 16, iw, ow); frombytes (ow, 16, cb);
	printf ("REF tf1024_ct "); hex (cb, 128); printf ("\n");
	decrypt_block (kw, tw, 16, ow, iw); frombytes (iw, 16, ob);
	printf ("REF tf1024_roundtrip %s\n", memcmp (ob, pb, 128) == 0 ? "YES" : "NO");

	/* 512 round-trip */
	unhex (tf512_kats[0][0], kb); unhex (tf512_kats[0][1], tb);
	unhex (tf512_kats[0][2], pb); unhex (tf512_kats[0][3], cb);
	towords (kb, 64, kw); towords (tb, 16, tw); towords (cb, 64, iw);
	decrypt_block (kw, tw, 8, iw, ow); frombytes (ow, 8, ob);
	printf ("REF tf512_roundtrip %s\n", memcmp (ob, pb, 64) == 0 ? "YES" : "NO");

	{ int rt = memcmp (ob, pb, 64) == 0; return (all && rt) ? 0 : 1; }
}
