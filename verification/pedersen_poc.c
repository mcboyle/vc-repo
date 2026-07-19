/*
 * pedersen_poc.c — Pedersen verifiable secret sharing (docs/VSS-SPEC.md,
 * IDEAS-BACKLOG.md "Sharing" row). Feldman VSS (step [31]) is binding but only
 * computationally hiding: a discrete-log break of C_j = g^{a_j} reveals the
 * coefficients, including the secret. Pedersen VSS (1991) blinds every
 * coefficient with a second polynomial under an independent generator h:
 *
 *   f(x) = s + a_1 x + ...,  b(x) = r + b_1 x + ...    (both mod q)
 *   C_j  = g^{a_j} h^{b_j} mod p,     share_i = (i, f(i), b(i))
 *   verify i:  g^{f(i)} h^{b(i)} == prod_j C_j^{(i^j mod q)}   (mod p)
 *
 * Perfectly hiding; binding while log_g(h) is unknown (g = 2^2, h = 3^2 here —
 * production derives h verifiably, e.g. hash-to-group). Same group/bignum as
 * feldman_poc.c. No standard KAT; proof = byte-identical agreement with
 * pedersen_reference.py + the verifiability properties.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct { uint64_t v[4]; } u256;

static const u256 P = { { 0x000000000002ff7fULL, 0, 0, 0x8000000000000000ULL } };
/* Q = (P-1)/2 */
static const u256 Q = { { 0x0000000000017fbfULL, 0, 0, 0x4000000000000000ULL } };

static int ucmp (const u256 *a, const u256 *b)
{ int i; for (i = 3; i >= 0; i--) { if (a->v[i] < b->v[i]) return -1; if (a->v[i] > b->v[i]) return 1; } return 0; }
static int uge (const u256 *a, const u256 *b) { return ucmp (a, b) >= 0; }

static void uadd (const u256 *a, const u256 *b, u256 *r)
{ unsigned __int128 c = 0; int i; for (i = 0; i < 4; i++) { c += (unsigned __int128) a->v[i] + b->v[i]; r->v[i] = (uint64_t) c; c >>= 64; } }
static void usub (const u256 *a, const u256 *b, u256 *r)
{ unsigned __int128 br = 0; int i; for (i = 0; i < 4; i++) { unsigned __int128 t = (unsigned __int128) a->v[i] - b->v[i] - br; r->v[i] = (uint64_t) t; br = (t >> 64) & 1; } }

static void addmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{ u256 t; uadd (a, b, &t); if (uge (&t, m)) usub (&t, m, &t); *r = t; }

/* full reduce of a 512-bit product (limbs prod[0..7]) mod m, MSB-first.
   The remainder is kept in 5 limbs so the bit shifted out of limb 3 (values in
   [2^255, m) when m ~ 2^255) is not lost; up to a few subtractions per bit bring
   it back below m. */
static void reduce512 (const uint64_t prod[8], const u256 *m, u256 *r)
{
	uint64_t rem[5]; int bit, k;
	memset (rem, 0, sizeof rem);
	for (bit = 511; bit >= 0; bit--) {
		uint64_t carry = (prod[bit >> 6] >> (bit & 63)) & 1, nc;
		for (k = 0; k < 5; k++) { nc = rem[k] >> 63; rem[k] = (rem[k] << 1) | carry; carry = nc; }
		/* subtract m while rem (5 limbs) >= m (4 limbs, rem[4] is the overflow bit) */
		for (;;) {
			u256 lo = { { rem[0], rem[1], rem[2], rem[3] } };
			int i; unsigned __int128 br = 0;
			if (rem[4] == 0 && !uge (&lo, m)) break;
			for (i = 0; i < 4; i++) { unsigned __int128 t = (unsigned __int128) rem[i] - m->v[i] - br; rem[i] = (uint64_t) t; br = (t >> 64) & 1; }
			rem[4] -= (uint64_t) br;
		}
	}
	r->v[0] = rem[0]; r->v[1] = rem[1]; r->v[2] = rem[2]; r->v[3] = rem[3];
}
static void mulmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	uint64_t prod[8]; unsigned __int128 c; int i, j;
	memset (prod, 0, sizeof prod);
	for (i = 0; i < 4; i++) {
		c = 0;
		for (j = 0; j < 4; j++) { unsigned __int128 t = (unsigned __int128) a->v[i] * b->v[j] + prod[i + j] + c; prod[i + j] = (uint64_t) t; c = t >> 64; }
		prod[i + 4] += (uint64_t) c;
	}
	reduce512 (prod, m, r);
}
static void powmod (const u256 *base, const u256 *exp, const u256 *m, u256 *r)
{
	u256 res = { { 1, 0, 0, 0 } }, b = *base; int i;
	for (i = 0; i < 256; i++) {
		if ((exp->v[i >> 6] >> (i & 63)) & 1) mulmod (&res, &b, m, &res);
		mulmod (&b, &b, m, &b);
	}
	*r = res;
}
/* modular inverse mod prime m via Fermat: a^(m-2) */
static void invmod (const u256 *a, const u256 *m, u256 *r)
{ u256 two = { { 2, 0, 0, 0 } }, e; usub (m, &two, &e); powmod (a, &e, m, r); }

static void small (uint64_t x, u256 *r) { r->v[0] = x; r->v[1] = r->v[2] = r->v[3] = 0; }
static int eq (const u256 *a, const u256 *b) { return ucmp (a, b) == 0; }

/* f(x) mod Q via Horner over t coefficients */
static void poly_eval (const u256 coeffs[], int t, uint64_t x, u256 *out)
{
	u256 r, xx; int i; small (0, &r); small (x, &xx);
	for (i = t - 1; i >= 0; i--) { mulmod (&r, &xx, &Q, &r); addmod (&r, &coeffs[i], &Q, &r); }
	*out = r;
}
static int verify_share (uint64_t i, const u256 *y, const u256 *z, const u256 commits[], int t)
{
	u256 lhs, lh2, rhs, term, e, ipow, g, h;
	int j;
	small (2, &g); mulmod (&g, &g, &P, &g);   /* g = 2^2 */
	small (3, &h); mulmod (&h, &h, &P, &h);   /* h = 3^2 */
	powmod (&g, y, &P, &lhs);
	powmod (&h, z, &P, &lh2);
	mulmod (&lhs, &lh2, &P, &lhs);            /* lhs = g^y h^z */
	small (1, &rhs); small (1, &ipow);        /* ipow = i^j mod Q, starts j=0 -> 1 */
	for (j = 0; j < t; j++) {
		e = ipow;
		powmod (&commits[j], &e, &P, &term);
		mulmod (&rhs, &term, &P, &rhs);
		{ u256 ii; small (i, &ii); mulmod (&ipow, &ii, &Q, &ipow); }
	}
	return eq (&lhs, &rhs);
}

static void hexout (const u256 *a) { int i; for (i = 3; i >= 0; i--) printf ("%016llx", (unsigned long long) a->v[i]); }
static void hexin (const char *s, u256 *r)
{ int len = (int) strlen (s), i; memset (r, 0, sizeof *r);
  for (i = 0; i < len; i++) { int d = s[i] <= '9' ? s[i]-'0' : (s[i]|32)-'a'+10; int pos = (len-1-i)*4; r->v[pos>>6] |= (uint64_t) d << (pos&63); } }

#define T 3
#define N 5

int main (void)
{
	u256 fc[T], bc2[T], commits[T], fsh[N], bsh[N], g, h;
	uint64_t xs[N] = { 1, 2, 3, 4, 5 };
	int i, all = 1;

	hexin ("c0ffee1234567890fedcba9876543210deadbeefcafebabe1029384756ab", &fc[0]);
	hexin ("1111111111111111111111111111111111111111111111111111111111", &fc[1]);
	hexin ("2222222222222222222222222222222222222222222222222222222222", &fc[2]);
	hexin ("5eed0000000000000000000000000000000000000000000000000000beef", &bc2[0]);
	hexin ("3333333333333333333333333333333333333333333333333333333333", &bc2[1]);
	hexin ("4444444444444444444444444444444444444444444444444444444444", &bc2[2]);

	small (2, &g); mulmod (&g, &g, &P, &g);
	small (3, &h); mulmod (&h, &h, &P, &h);
	for (i = 0; i < T; i++) {
		u256 cg, ch;
		powmod (&g, &fc[i], &P, &cg);
		powmod (&h, &bc2[i], &P, &ch);
		mulmod (&cg, &ch, &P, &commits[i]);
	}
	for (i = 0; i < N; i++) { poly_eval (fc, T, xs[i], &fsh[i]); poly_eval (bc2, T, xs[i], &bsh[i]); }

	for (i = 0; i < T; i++) { printf ("REF commit_%d ", i); hexout (&commits[i]); printf ("\n"); }
	for (i = 0; i < N; i++) { printf ("REF share_%llu ", (unsigned long long) xs[i]); hexout (&fsh[i]); printf (" "); hexout (&bsh[i]); printf ("\n"); }

	for (i = 0; i < N; i++) if (!verify_share (xs[i], &fsh[i], &bsh[i], commits, T)) all = 0;
	printf ("REF all_shares_verify %s\n", all ? "YES" : "NO");

	{ u256 bad = fsh[2]; bad.v[0] ^= 1; printf ("REF tampered_f_rejected %s\n", !verify_share (3, &bad, &bsh[2], commits, T) ? "YES" : "NO"); }
	{ u256 bad = bsh[2]; bad.v[0] ^= 1; printf ("REF tampered_b_rejected %s\n", !verify_share (3, &fsh[2], &bad, commits, T) ? "YES" : "NO"); }

	/* reconstruct secret from f-shares {1,3,5} via Lagrange at 0, mod Q */
	{
		int idx[T] = { 0, 2, 4 }, a, b;
		u256 s2, secmod; small (0, &s2);
		for (a = 0; a < T; a++) {
			u256 num, den, term, inv; small (1, &num); small (1, &den);
			for (b = 0; b < T; b++) {
				if (a == b) continue;
				{ u256 xj, negxj; small (xs[idx[b]], &xj); usub (&Q, &xj, &negxj); mulmod (&num, &negxj, &Q, &num); }
				{ u256 xi, xj, diff; small (xs[idx[a]], &xi); small (xs[idx[b]], &xj);
				  if (uge (&xi, &xj)) usub (&xi, &xj, &diff); else { usub (&xj, &xi, &diff); usub (&Q, &diff, &diff); }
				  mulmod (&den, &diff, &Q, &den); }
			}
			invmod (&den, &Q, &inv);
			mulmod (&num, &inv, &Q, &term);
			mulmod (&term, &fsh[idx[a]], &Q, &term);
			addmod (&s2, &term, &Q, &s2);
		}
		secmod = fc[0]; if (uge (&secmod, &Q)) usub (&secmod, &Q, &secmod);
		printf ("REF reconstruct_t %s\n", eq (&s2, &secmod) ? "YES" : "NO");

		/* below threshold: shares {1,2} */
		{
			int idx2[2] = { 0, 1 }, na = 2;
			u256 s3; small (0, &s3);
			for (a = 0; a < na; a++) {
				u256 num, den, term, inv; small (1, &num); small (1, &den);
				for (b = 0; b < na; b++) {
					if (a == b) continue;
					{ u256 xj, negxj; small (xs[idx2[b]], &xj); usub (&Q, &xj, &negxj); mulmod (&num, &negxj, &Q, &num); }
					{ u256 xi, xj, diff; small (xs[idx2[a]], &xi); small (xs[idx2[b]], &xj);
					  if (uge (&xi, &xj)) usub (&xi, &xj, &diff); else { usub (&xj, &xi, &diff); usub (&Q, &diff, &diff); }
					  mulmod (&den, &diff, &Q, &den); }
				}
				invmod (&den, &Q, &inv);
				mulmod (&num, &inv, &Q, &term);
				mulmod (&term, &fsh[idx2[a]], &Q, &term);
				addmod (&s3, &term, &Q, &s3);
			}
			printf ("REF below_threshold_wrong %s\n", !eq (&s3, &secmod) ? "YES" : "NO");
		}
	}
	return all ? 0 : 1;
}
