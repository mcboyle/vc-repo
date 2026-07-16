/*
 * Shamir Secret Sharing over GF(2^8) — see Shamir.h.
 */

#include "Shamir.h"
#include <string.h>

/* ---- GF(2^8) with reduction polynomial 0x11B (AES), generator 0x03 ---- */

static unsigned char gf_exp[512];
static unsigned char gf_log[256];
static int gf_ready = 0;

static void gf_init (void)
{
	int i;
	unsigned int x = 1;
	for (i = 0; i < 255; i++)
	{
		gf_exp[i] = (unsigned char) x;
		gf_log[x] = (unsigned char) i;
		/* multiply x by the generator 0x03 in GF(2^8): x = x*2 XOR x, reduce by 0x11B */
		{
			unsigned int hi = x & 0x80;
			x = (x << 1) & 0xff;
			if (hi) x ^= 0x1b;      /* reduce (0x11B without the x^8 bit) */
			x ^= gf_exp[i];         /* + original (i.e. *3 = *2 + *1) */
		}
	}
	/* extend the exp table so log sums up to 508 don't need a modulo in the hot path */
	for (i = 255; i < 512; i++)
		gf_exp[i] = gf_exp[i - 255];
	gf_log[0] = 0;                   /* unused; log(0) undefined */
	gf_ready = 1;
}

static unsigned char gf_mul (unsigned char a, unsigned char b)
{
	if (a == 0 || b == 0) return 0;
	return gf_exp[gf_log[a] + gf_log[b]];
}

/* multiplicative inverse: a^(-1) = g^(255 - log a) */
static unsigned char gf_inv (unsigned char a)
{
	/* a != 0 required by callers */
	return gf_exp[255 - gf_log[a]];
}

/* Evaluate the polynomial with coefficients coef[0..degree] at point x (Horner). */
static unsigned char gf_poly_eval (const unsigned char *coef, int degree, unsigned char x)
{
	unsigned char r = coef[degree];
	int i;
	for (i = degree - 1; i >= 0; i--)
		r = (unsigned char) (gf_mul (r, x) ^ coef[i]);
	return r;
}

int shamir_split (const unsigned char *secret, int secret_len,
                  int threshold, int n_shares,
                  const unsigned char *random_bytes,
                  ShamirShare *shares_out)
{
	int b, s, k;

	if (!secret || !random_bytes || !shares_out) return SHAMIR_ERR_PARAM;
	if (secret_len < 1 || secret_len > SHAMIR_MAX_SECRET) return SHAMIR_ERR_PARAM;
	if (threshold < 2 || n_shares < threshold || n_shares > SHAMIR_MAX_SHARES) return SHAMIR_ERR_PARAM;

	if (!gf_ready) gf_init();

	for (s = 0; s < n_shares; s++)
	{
		shares_out[s].x = (unsigned char) (s + 1);   /* distinct nonzero x = 1..n */
		shares_out[s].len = secret_len;
	}

	/* Each secret byte gets its own polynomial: coef[0] = secret byte, coef[1..t-1] = random. */
	for (b = 0; b < secret_len; b++)
	{
		unsigned char coef[SHAMIR_MAX_SHARES];   /* threshold <= SHAMIR_MAX_SHARES */
		coef[0] = secret[b];
		for (k = 1; k < threshold; k++)
			coef[k] = random_bytes[(k - 1) * secret_len + b];

		for (s = 0; s < n_shares; s++)
			shares_out[s].y[b] = gf_poly_eval (coef, threshold - 1, shares_out[s].x);

		{ volatile unsigned char *p = coef; size_t n = sizeof (coef); while (n--) *p++ = 0; }
	}

	return SHAMIR_OK;
}

int shamir_combine (const ShamirShare *shares, int count,
                    unsigned char *secret_out, int *secret_len_out)
{
	int i, j, b, len;

	if (!shares || !secret_out || count < 2 || count > SHAMIR_MAX_SHARES) return SHAMIR_ERR_PARAM;
	len = shares[0].len;
	if (len < 1 || len > SHAMIR_MAX_SECRET) return SHAMIR_ERR_PARAM;
	for (i = 0; i < count; i++)
	{
		if (shares[i].len != len || shares[i].x == 0) return SHAMIR_ERR_PARAM;
		for (j = i + 1; j < count; j++)
			if (shares[i].x == shares[j].x) return SHAMIR_ERR_PARAM;   /* x must be distinct */
	}

	if (!gf_ready) gf_init();

	/* Lagrange interpolation at x = 0, per secret byte:
	   secret = sum_i y_i * prod_{j!=i} x_j / (x_j - x_i)   (subtraction == XOR in GF(2^8)) */
	for (b = 0; b < len; b++)
	{
		unsigned char acc = 0;
		for (i = 0; i < count; i++)
		{
			unsigned char num = 1, den = 1;
			for (j = 0; j < count; j++)
			{
				if (j == i) continue;
				num = gf_mul (num, shares[j].x);
				den = gf_mul (den, (unsigned char) (shares[j].x ^ shares[i].x));
			}
			{
				unsigned char li = gf_mul (num, gf_inv (den));      /* Lagrange basis at 0 */
				acc ^= gf_mul (shares[i].y[b], li);
			}
		}
		secret_out[b] = acc;
	}

	if (secret_len_out) *secret_len_out = len;
	return SHAMIR_OK;
}
