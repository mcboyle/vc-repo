/*
 * SHA-3 (Keccak) — FIPS 202, SHA3-512 variant. Public domain (CC0).
 * See Sha3.h for design notes (endian-portable absorb/squeeze).
 */

#include "Sha3.h"

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

/* Keccak-f[1600] round constants (iota). */
static const uint64 keccakf_rndc[24] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rho rotation offsets. */
static const int keccakf_rotc[24] =
{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

/* Pi lane permutation. */
static const int keccakf_piln[24] =
{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccakf (uint64 st[25])
{
	int i, j, r;
	uint64 t, bc[5];

	for (r = 0; r < 24; r++)
	{
		/* Theta */
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

		for (i = 0; i < 5; i++)
		{
			t = bc[(i + 4) % 5] ^ ROTL64 (bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		/* Rho and Pi */
		t = st[1];
		for (i = 0; i < 24; i++)
		{
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64 (t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5)
		{
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		/* Iota */
		st[0] ^= keccakf_rndc[r];
	}
}

void sha3_512_init (SHA3_CTX *ctx)
{
	int i;
	for (i = 0; i < 25; i++)
		ctx->st[i] = 0;
	ctx->pt = 0;
	ctx->rsiz = SHA3_512_BLOCKSIZE;    /* 72 */
	ctx->mdlen = SHA3_512_DIGESTSIZE;  /* 64 */
}

void sha3_512_update (SHA3_CTX *ctx, const unsigned char *in, size_t inlen)
{
	size_t i;
	int j = ctx->pt;

	for (i = 0; i < inlen; i++)
	{
		/* XOR input byte into little-endian lane position j (endian-portable) */
		ctx->st[j >> 3] ^= (uint64) in[i] << (8 * (j & 7));
		j++;
		if (j >= ctx->rsiz)
		{
			keccakf (ctx->st);
			j = 0;
		}
	}
	ctx->pt = j;
}

void sha3_512_final (SHA3_CTX *ctx, unsigned char *md)
{
	int i;

	/* pad10*1 with SHA-3 domain separation (0x06 ... 0x80) */
	ctx->st[ctx->pt >> 3] ^= (uint64) 0x06 << (8 * (ctx->pt & 7));
	ctx->st[(ctx->rsiz - 1) >> 3] ^= (uint64) 0x80 << (8 * ((ctx->rsiz - 1) & 7));

	keccakf (ctx->st);

	/* squeeze: mdlen (64) <= rate (72), so a single squeeze suffices */
	for (i = 0; i < ctx->mdlen; i++)
		md[i] = (unsigned char) ((ctx->st[i >> 3] >> (8 * (i & 7))) & 0xFF);
}
