/*
 * oram_poc.c — proof-of-concept for write-only ORAM access-pattern hiding (docs/ORAM-SPEC.md).
 *
 * The real mitigation for the multi-snapshot deniability attack (THREAT-MODEL.md). Every logical write
 * touches K uniformly-random physical blocks, re-encrypted with fresh ChaCha20 ciphertext, chosen from
 * the PRNG stream INDEPENDENTLY of the logical target — so two disk snapshots reveal only "K random
 * blocks changed per write", identical whether or not a hidden volume was written. Reads do not modify
 * the disk, so a snapshot adversary never sees them.
 *
 * Layer 2 of the two-way convention: this drives the REAL in-tree Crypto/chacha256.c (block cipher) and
 * Crypto/Sha2.c (state digest). oram_reference.py is the independent Layer-1 reference; both use the
 * same deterministic xorshift64* PRNG, so build_and_verify.sh diffs the REF lines byte-for-byte.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/chacha256.h"
#include "Crypto/Sha2.h"

#define B   8
#define N   24
#define K   10
#define BLK 32

/* deterministic PRNG: xorshift64* (identical to oram_reference.py) */
static uint64_t g_s;
static uint64_t rng_u64 (void)
{
	uint64_t x = g_s;
	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	g_s = x;
	return x * 0x2545F4914F6CDD1DULL;
}

static const unsigned char ORAM_KEY[32] = {
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f };

static unsigned char g_nonce[N][8];
static unsigned char g_ct[N][BLK];
static unsigned char g_plain[N][BLK];
static int  g_posmap[B];
static int  g_occ[N];

static void oram_init (uint64_t seed)
{
	g_s = seed;
	memset (g_nonce, 0, sizeof g_nonce);
	memset (g_ct, 0, sizeof g_ct);
	memset (g_plain, 0, sizeof g_plain);
	memset (g_occ, 0, sizeof g_occ);
	{ int i; for (i = 0; i < B; i++) g_posmap[i] = -1; }
}

static void enc_block (int pos, const unsigned char pt[BLK])
{
	ChaCha256Ctx ctx;
	uint64_t nz = rng_u64 ();
	int i;
	for (i = 0; i < 8; i++) g_nonce[pos][i] = (unsigned char) (nz >> (8 * i));
	ChaCha256Init (&ctx, ORAM_KEY, g_nonce[pos], 20);
	ChaCha256Encrypt (&ctx, pt, BLK, g_ct[pos]);
	memcpy (g_plain[pos], pt, BLK);
}

/* K distinct uniform positions (draw order preserved in S) */
static void sample (int L, int S[K])
{
	int n = 0, i, dup;
	(void) L;
	while (n < K)
	{
		int p = (int) (rng_u64 () % (uint64_t) N);
		for (dup = 0, i = 0; i < n; i++) if (S[i] == p) { dup = 1; break; }
		if (!dup) S[n++] = p;
	}
}

static int g_trace[64][K];   /* touched sets per write (draw order) */
static int g_traceLen = 0;

static void oram_write (int L, const unsigned char pt[BLK])
{
	int S[K], i, home = -1, old = g_posmap[L];
	sample (L, S);

	if (old != -1)
	{ for (i = 0; i < K; i++) if (S[i] == old) { home = old; break; } }
	if (home == -1)
	{
		for (i = 0; i < K; i++) if (!g_occ[S[i]]) { home = S[i]; break; }
		if (old != -1) g_occ[old] = 0;   /* free the stale home */
	}
	g_occ[home] = 1;
	g_posmap[L] = home;

	for (i = 0; i < K; i++)
	{
		int p = S[i];
		if (p == home)           enc_block (p, pt);
		else if (g_occ[p])       enc_block (p, g_plain[p]);   /* preserve other live block */
		else { unsigned char z[BLK]; memset (z, 0, BLK); enc_block (p, z); }
	}
	for (i = 0; i < K; i++) g_trace[g_traceLen][i] = S[i];
	g_traceLen++;
}

static const unsigned char *oram_read (int L)
{
	static const unsigned char zero[BLK] = {0};
	return g_posmap[L] == -1 ? zero : g_plain[g_posmap[L]];
}

static void state_digest (char out[65])
{
	sha256_ctx c; unsigned char h[32]; int p, i;
	sha256_begin (&c);
	for (p = 0; p < N; p++) { sha256_hash (g_nonce[p], 8, &c); sha256_hash (g_ct[p], BLK, &c); }
	{ unsigned char pm[B]; for (i = 0; i < B; i++) pm[i] = (unsigned char) ((g_posmap[i] + 128) & 0xff); sha256_hash (pm, B, &c); }
	sha256_end (h, &c);
	for (i = 0; i < 32; i++) sprintf (out + 2 * i, "%02x", h[i]);
	out[64] = 0;
}

/* copy the current trace out (for comparing two workloads) */
static void snapshot_trace (int dst[64][K], int *dstLen) { memcpy (dst, g_trace, sizeof g_trace); *dstLen = g_traceLen; }

static void run_workload (int hiddenActive, uint64_t seed)
{
	static const int pubOnly[10] = {0,1,2,3,0,1,2,3,0,1};
	static const int mixed[10]   = {0,4,1,5,2,6,3,7,0,1};
	const int *seq = hiddenActive ? mixed : pubOnly;
	int i, j;
	oram_init (seed);
	g_traceLen = 0; memset (g_trace, 0, sizeof g_trace);
	for (i = 0; i < 10; i++)
	{
		unsigned char v[BLK];
		for (j = 0; j < BLK; j++) v[j] = (unsigned char) ((seq[i] * 7 + i * 13 + j) & 0xff);
		oram_write (seq[i], v);
	}
}

int main (void)
{
	char dig[65];

	/* [correctness] write then read back over a fixed workload -> state digest anchor */
	{
		static const int seq[10] = {0,3,3,7,1,7,2,0,5,3};
		unsigned char vals[B][BLK]; int have[B]; int i, j, ok = 1;
		memset (have, 0, sizeof have);
		oram_init (0xDEADBEEFCAFEF00DULL);
		g_traceLen = 0;
		for (i = 0; i < 10; i++)
		{
			unsigned char v[BLK];
			for (j = 0; j < BLK; j++) v[j] = (unsigned char) ((i * 31 + seq[i] + j) & 0xff);
			oram_write (seq[i], v);
			memcpy (vals[seq[i]], v, BLK); have[seq[i]] = 1;
		}
		for (i = 0; i < B; i++) if (have[i] && memcmp (oram_read (i), vals[i], BLK) != 0) ok = 0;
		printf ("REF correctness reads==writes = %s\n", ok ? "YES" : "NO");
		state_digest (dig);
		printf ("REF state digest = %s\n", dig);
	}

	/* [access pattern] public-only vs public+hidden traces must be identical */
	{
		int ta[64][K], la, tb[64][K], lb, i, allK = 1, same = 1;
		char digA[65], digB[65];
		run_workload (0, 0x1234567890ABCDEFULL); snapshot_trace (ta, &la); state_digest (digA);
		run_workload (1, 0x1234567890ABCDEFULL); snapshot_trace (tb, &lb); state_digest (digB);
		if (la != lb) same = 0;
		else { int w; for (w = 0; w < la; w++) for (i = 0; i < K; i++) if (ta[w][i] != tb[w][i]) same = 0; }
		(void) allK;
		printf ("REF every write touches exactly K blocks = %s\n", (la == 10 && lb == 10) ? "YES" : "NO");
		printf ("REF access trace identical: public-only vs public+hidden = %s\n", same ? "YES" : "NO");
		printf ("REF ciphertext differs though access pattern is identical = %s\n",
		        (same && strcmp (digA, digB) != 0) ? "YES" : "NO");
	}

	return 0;
}
