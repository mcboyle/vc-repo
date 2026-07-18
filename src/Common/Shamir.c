/*
 * Shamir Secret Sharing over GF(2^8) — see Shamir.h.
 */

#include "Shamir.h"
#include <string.h>

/* ---- GF(2^8), reduction polynomial 0x11B (AES) — constant-time, no tables ----
 *
 * Both operands in the reconstruction path are secret (share bytes and Lagrange terms), so the
 * multiply and inverse must not branch on, nor index memory by, secret values. The previous
 * table-based `gf_exp[gf_log[a] + gf_log[b]]` with an `if (a==0||b==0)` early-out leaked through cache
 * timing and branch prediction — a side channel in the strongest coercion primitive. These
 * fixed-iteration, branchless, table-free versions remove that channel while computing byte-identical
 * field results (same AES field, reduction 0x1b), so every existing KAT and share value is unchanged.
 */

/* a * b in GF(2^8): Russian-peasant multiply, reduction 0x1b. Fixed 8 iterations; the only branches
   are on the loop counter, never on a or b; no table lookups. */
static unsigned char gf_mul (unsigned char a, unsigned char b)
{
	unsigned char p = 0;
	int i;
	for (i = 0; i < 8; i++)
	{
		unsigned char mask = (unsigned char) (0u - (unsigned) (b & 1u));      /* 0x00 or 0xFF */
		unsigned char hi   = (unsigned char) (0u - (unsigned) ((a >> 7) & 1u)) & 0x1b;
		p ^= mask & a;                                                        /* if (b&1) p ^= a   */
		a  = (unsigned char) (((unsigned) a << 1) ^ hi);                      /* a = xtime(a)      */
		b  = (unsigned char) (b >> 1);
	}
	return p;
}

/* a^(-1) = a^254 in GF(2^8) for a != 0 (Fermat: a^255 = 1). The exponent 254 is a public constant, so
   the square-and-multiply schedule is fixed and independent of the secret a; a == 0 maps to 0. */
static unsigned char gf_inv (unsigned char a)
{
	unsigned char r = 1, base = a;
	int i;
	for (i = 0; i < 8; i++)
	{
		if ((254u >> i) & 1u)        /* schedule depends only on the constant 254, not on a */
			r = gf_mul (r, base);
		base = gf_mul (base, base);
	}
	return r;
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
