/*
 * AesCt.c — see AesCt.h. Constant-time AES-256, VeraCrypt style, gated VC_ENABLE_CTAES.
 *
 * Self-contained: the constant-time GF(2^8) multiply/inverse below are the SAME branchless, table-free
 * construction proven in src/Common/Shamir.c (dudect + ctgrind clean, step [41]) — kept local so this
 * Crypto module has no dependency on Common. The copy is independently proven correct AND constant-time
 * in suite step [88] (FIPS-197 KAT + byte-for-byte agreement with the real Gladman AES + ctgrind CLEAN),
 * and src/Common/AesCt.c is on the ct-primitive-guard allowlist for exactly that reason.
 */

#include "AesCt.h"

#if defined(VC_ENABLE_CTAES)

#include <string.h>

/* a * b in GF(2^8), reduction 0x1b; fixed 8 iterations, branchless (mask, not `if`), no tables. */
static unsigned char gf_mul (unsigned char a, unsigned char b)
{
	unsigned char p = 0;
	int i;
	for (i = 0; i < 8; i++)
	{
		unsigned char mask = (unsigned char) (0u - (unsigned) (b & 1u));            /* 0x00 or 0xFF */
		unsigned char hi   = (unsigned char) (0u - (unsigned) ((a >> 7) & 1u)) & 0x1b;
		p ^= mask & a;
		a  = (unsigned char) (((unsigned) a << 1) ^ hi);
		b  = (unsigned char) (b >> 1);
	}
	return p;
}

/* a^(-1) = a^254 in GF(2^8) (a==0 -> 0); fixed square-multiply schedule on the public exponent 254. */
static unsigned char gf_inv (unsigned char a)
{
	unsigned char r = 1, base = a;
	int i;
	for (i = 0; i < 8; i++)
	{
		if ((254u >> i) & 1u)          /* schedule depends only on the constant 254, not on a */
			r = gf_mul (r, base);
		base = gf_mul (base, base);
	}
	return r;
}

static unsigned char rotl8 (unsigned char x, int n) { return (unsigned char) ((x << n) | (x >> (8 - n))); }

/* S(x) = affine( gf_inv(x) ) — the only table AES indexed by secret data; here it is arithmetic. */
static unsigned char sbox (unsigned char x)
{
	unsigned char b = gf_inv (x);
	return (unsigned char) (b ^ rotl8 (b, 1) ^ rotl8 (b, 2) ^ rotl8 (b, 3) ^ rotl8 (b, 4) ^ 0x63);
}

/* xtime: multiply by x in GF(2^8), branch-free. */
static unsigned char xtime (unsigned char a)
{
	return (unsigned char) (((unsigned) a << 1) ^ (0x1bu & (unsigned) (0u - (unsigned) ((a >> 7) & 1u))));
}

void AesCtInit256 (AesCtKey256 *ctx, const unsigned char key[32])
{
	static const unsigned char Rcon[8] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
	unsigned char w[60][4];
	int i, k;
	for (i = 0; i < 8; i++) for (k = 0; k < 4; k++) w[i][k] = key[4*i + k];
	for (i = 8; i < 60; i++)
	{
		unsigned char t[4];
		for (k = 0; k < 4; k++) t[k] = w[i-1][k];
		if (i % 8 == 0)
		{
			unsigned char tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;   /* RotWord */
			for (k = 0; k < 4; k++) t[k] = sbox (t[k]);                                    /* SubWord */
			t[0] = (unsigned char) (t[0] ^ Rcon[i/8]);
		}
		else if (i % 8 == 4)
		{
			for (k = 0; k < 4; k++) t[k] = sbox (t[k]);
		}
		for (k = 0; k < 4; k++) w[i][k] = (unsigned char) (w[i-8][k] ^ t[k]);
	}
	for (i = 0; i < 60; i++) for (k = 0; k < 4; k++) ctx->rk[4*i + k] = w[i][k];
}

/* state byte index = 4*col + row (FIPS-197). */
static void shift_rows (unsigned char s[16])
{
	unsigned char t[16];
	int r, c;
	for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) t[4*c + r] = s[4*((c + r) & 3) + r];
	memcpy (s, t, 16);
}

static void mix_columns (unsigned char s[16])
{
	int c;
	for (c = 0; c < 4; c++)
	{
		unsigned char *p = s + 4*c;
		unsigned char a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
		p[0] = (unsigned char) (xtime (a0) ^ (xtime (a1) ^ a1) ^ a2 ^ a3);
		p[1] = (unsigned char) (a0 ^ xtime (a1) ^ (xtime (a2) ^ a2) ^ a3);
		p[2] = (unsigned char) (a0 ^ a1 ^ xtime (a2) ^ (xtime (a3) ^ a3));
		p[3] = (unsigned char) ((xtime (a0) ^ a0) ^ a1 ^ a2 ^ xtime (a3));
	}
}

void AesCtEncryptBlock (const AesCtKey256 *ctx, const unsigned char in[16], unsigned char out[16])
{
	unsigned char s[16];
	int round, i;
	memcpy (s, in, 16);
	for (i = 0; i < 16; i++) s[i] ^= ctx->rk[i];                       /* AddRoundKey (round 0) */
	for (round = 1; round < AESCT_ROUNDS_256; round++)
	{
		for (i = 0; i < 16; i++) s[i] = sbox (s[i]);                   /* SubBytes */
		shift_rows (s);
		mix_columns (s);
		for (i = 0; i < 16; i++) s[i] ^= ctx->rk[16*round + i];        /* AddRoundKey */
	}
	for (i = 0; i < 16; i++) s[i] = sbox (s[i]);                       /* final round: no MixColumns */
	shift_rows (s);
	for (i = 0; i < 16; i++) s[i] ^= ctx->rk[16*AESCT_ROUNDS_256 + i];
	memcpy (out, s, 16);
}

void AesCtEncrypt256 (const unsigned char key[32], const unsigned char in[16], unsigned char out[16])
{
	AesCtKey256 ctx;
	AesCtInit256 (&ctx, key);
	AesCtEncryptBlock (&ctx, in, out);
	{ volatile unsigned char *p = (volatile unsigned char *) &ctx; size_t n = sizeof ctx; while (n--) *p++ = 0; }
}

/* ---- inverse cipher (decrypt) ---- */

/* inverse S-box: S^{-1}(y) = gf_inv( invAffine(y) ), invAffine(y) = rotl(y,1) ^ rotl(y,3) ^ rotl(y,6) ^ 0x05 */
static unsigned char inv_sbox (unsigned char y)
{
	unsigned char b = (unsigned char) (rotl8 (y, 1) ^ rotl8 (y, 3) ^ rotl8 (y, 6) ^ 0x05);
	return gf_inv (b);
}

/* InvShiftRows: row r cyclically RIGHT-shifted by r (inverse of ShiftRows). */
static void inv_shift_rows (unsigned char s[16])
{
	unsigned char t[16];
	int r, c;
	for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) t[4*c + r] = s[4*((c - r) & 3) + r];
	memcpy (s, t, 16);
}

/* InvMixColumns: multiply each column by [0e 0b 0d 09] (rotated), via the branchless gf_mul. */
static void inv_mix_columns (unsigned char s[16])
{
	int c;
	for (c = 0; c < 4; c++)
	{
		unsigned char *p = s + 4*c;
		unsigned char a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
		p[0] = (unsigned char) (gf_mul (a0, 0x0e) ^ gf_mul (a1, 0x0b) ^ gf_mul (a2, 0x0d) ^ gf_mul (a3, 0x09));
		p[1] = (unsigned char) (gf_mul (a0, 0x09) ^ gf_mul (a1, 0x0e) ^ gf_mul (a2, 0x0b) ^ gf_mul (a3, 0x0d));
		p[2] = (unsigned char) (gf_mul (a0, 0x0d) ^ gf_mul (a1, 0x09) ^ gf_mul (a2, 0x0e) ^ gf_mul (a3, 0x0b));
		p[3] = (unsigned char) (gf_mul (a0, 0x0b) ^ gf_mul (a1, 0x0d) ^ gf_mul (a2, 0x09) ^ gf_mul (a3, 0x0e));
	}
}

void AesCtDecryptBlock (const AesCtKey256 *ctx, const unsigned char in[16], unsigned char out[16])
{
	unsigned char s[16];
	int round, i;
	memcpy (s, in, 16);
	for (i = 0; i < 16; i++) s[i] ^= ctx->rk[16*AESCT_ROUNDS_256 + i];   /* AddRoundKey (last) */
	for (round = AESCT_ROUNDS_256 - 1; round >= 1; round--)
	{
		inv_shift_rows (s);
		for (i = 0; i < 16; i++) s[i] = inv_sbox (s[i]);
		for (i = 0; i < 16; i++) s[i] ^= ctx->rk[16*round + i];
		inv_mix_columns (s);
	}
	inv_shift_rows (s);
	for (i = 0; i < 16; i++) s[i] = inv_sbox (s[i]);
	for (i = 0; i < 16; i++) s[i] ^= ctx->rk[i];
	memcpy (out, s, 16);
}

void AesCtDecrypt256 (const unsigned char key[32], const unsigned char in[16], unsigned char out[16])
{
	AesCtKey256 ctx;
	AesCtInit256 (&ctx, key);
	AesCtDecryptBlock (&ctx, in, out);
	{ volatile unsigned char *p = (volatile unsigned char *) &ctx; size_t n = sizeof ctx; while (n--) *p++ = 0; }
}

#endif /* VC_ENABLE_CTAES */
