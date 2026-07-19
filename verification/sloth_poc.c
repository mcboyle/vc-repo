/*
 * sloth_poc.c — Sloth verifiable delay function (docs/DELAY-SPEC.md,
 * IDEAS-BACKLOG.md "Delay functions" row). Sloth (Lenstra & Wesolowski, 2015):
 * computing the chain takes T inherently SEQUENTIAL modular-sqrt steps (each a
 * full modexp over a prime p ≡ 3 mod 4), but VERIFYING takes T cheap squarings.
 * A coercer cannot parallelize past the delay; the holder verifies instantly —
 * the "coercion cooling-off" a delay factor needs.
 *
 * NOT in the VeraCrypt tree and no standard KAT exists; the proof is (like the
 * network-share/OPRF number-theory PoCs) byte-identical agreement between this C
 * and sloth_reference.py, plus the defining invertibility (verify recovers the
 * seed) and the fast-vs-slow asymmetry (forward = modexp/step; verify =
 * modsqr/step). 256-bit fixed-width bignum (undersized for production).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* --- 256-bit unsigned as 4 x 64-bit limbs (little-endian limb order) --- */
typedef struct { uint64_t v[4]; } u256;

static const u256 P = { { 0x000000000000005fULL, 0, 0, 0x8000000000000000ULL } };

static int ucmp (const u256 *a, const u256 *b)
{ int i; for (i = 3; i >= 0; i--) { if (a->v[i] < b->v[i]) return -1; if (a->v[i] > b->v[i]) return 1; } return 0; }

static int uge (const u256 *a, const u256 *b) { return ucmp (a, b) >= 0; }

static void uadd (const u256 *a, const u256 *b, u256 *r)
{
	unsigned __int128 c = 0; int i;
	for (i = 0; i < 4; i++) { c += (unsigned __int128) a->v[i] + b->v[i]; r->v[i] = (uint64_t) c; c >>= 64; }
}
static void usub (const u256 *a, const u256 *b, u256 *r)
{
	unsigned __int128 br = 0; int i;
	for (i = 0; i < 4; i++) { unsigned __int128 t = (unsigned __int128) a->v[i] - b->v[i] - br; r->v[i] = (uint64_t) t; br = (t >> 64) & 1; }
}
static void addmod (const u256 *a, const u256 *b, u256 *r)
{ u256 t; uadd (a, b, &t); if (uge (&t, &P)) usub (&t, &P, &t); *r = t; }

/* schoolbook 256x256 -> 512, then reduce mod P by long division (PoC clarity) */
static void mulmod (const u256 *a, const u256 *b, u256 *r)
{
	uint64_t prod[8]; unsigned __int128 c; int i, j, bit;
	u256 rem;
	memset (prod, 0, sizeof prod);
	for (i = 0; i < 4; i++) {
		c = 0;
		for (j = 0; j < 4; j++) {
			unsigned __int128 t = (unsigned __int128) a->v[i] * b->v[j] + prod[i + j] + c;
			prod[i + j] = (uint64_t) t; c = t >> 64;
		}
		prod[i + 4] += (uint64_t) c;
	}
	/* reduce the 512-bit product mod P, MSB-first binary long division */
	memset (&rem, 0, sizeof rem);
	for (bit = 511; bit >= 0; bit--) {
		u256 sh; int k; uint64_t carry;
		/* rem = rem << 1 | bit(prod) */
		carry = (prod[bit >> 6] >> (bit & 63)) & 1;
		for (k = 0; k < 4; k++) { uint64_t nc = rem.v[k] >> 63; sh.v[k] = (rem.v[k] << 1) | carry; carry = nc; }
		rem = sh;
		if (uge (&rem, &P)) usub (&rem, &P, &rem);
	}
	*r = rem;
}

/* r = base^exp mod P */
static void powmod (const u256 *base, const u256 *exp, u256 *r)
{
	u256 res = { { 1, 0, 0, 0 } }, b = *base; int i, bit;
	for (i = 0; i < 256; i++) {
		bit = (exp->v[i >> 6] >> (i & 63)) & 1;
		if (bit) mulmod (&res, &b, &res);
		mulmod (&b, &b, &b);
	}
	*r = res;
}

static int is_zero (const u256 *a) { return (a->v[0] | a->v[1] | a->v[2] | a->v[3]) == 0; }
static int is_odd (const u256 *a) { return a->v[0] & 1; }
static void neg_mod (const u256 *a, u256 *r) { if (is_zero (a)) { *r = *a; } else usub (&P, a, r); }

/* (P-1)/2 and (P+1)/4 as constants derived from P */
static void half_pm1 (u256 *r) { u256 one = { { 1, 0, 0, 0 } }, t; usub (&P, &one, &t); /* P-1 */
	int i; uint64_t carry = 0; for (i = 3; i >= 0; i--) { uint64_t nb = (t.v[i] & 1) << 63; r->v[i] = (t.v[i] >> 1) | carry; carry = nb; } }
static void quarter_pp1 (u256 *r) { u256 one = { { 1, 0, 0, 0 } }, t; uadd (&P, &one, &t); /* P+1 */
	int s, i; for (s = 0; s < 2; s++) { uint64_t carry = 0; for (i = 3; i >= 0; i--) { uint64_t nb = (t.v[i] & 1) << 63; t.v[i] = (t.v[i] >> 1) | carry; carry = nb; } } *r = t; }

static int is_qr (const u256 *x, const u256 *e_half)
{ u256 t; powmod (x, e_half, &t); return t.v[0] == 1 && t.v[1] == 0 && t.v[2] == 0 && t.v[3] == 0; }

static void sqrt_perm (const u256 *x, const u256 *e_half, const u256 *e_quarter, u256 *out)
{
	int b = is_qr (x, e_half);
	u256 base, y;
	if (b) base = *x; else neg_mod (x, &base);
	powmod (&base, e_quarter, &y);
	if ((int)(y.v[0] & 1) != b) neg_mod (&y, &y);
	*out = y;
}
static void sqrt_perm_inv (const u256 *y, u256 *out)
{
	int b = is_odd (y);
	u256 base; mulmod (y, y, &base);
	if (b) *out = base; else neg_mod (&base, out);
}

static void hexin (const char *s, u256 *r)
{
	int len = (int) strlen (s), i;
	memset (r, 0, sizeof *r);
	for (i = 0; i < len; i++) {
		int d = s[i] <= '9' ? s[i] - '0' : (s[i] | 32) - 'a' + 10;
		int pos = (len - 1 - i) * 4;
		r->v[pos >> 6] |= (uint64_t) d << (pos & 63);
	}
}
static void hexout (const u256 *a) { int i; for (i = 3; i >= 0; i--) printf ("%016llx", (unsigned long long) a->v[i]); }
static int eq (const u256 *a, const u256 *b) { return ucmp (a, b) == 0; }

#define STEPS 500

int main (void)
{
	u256 e_half, e_quarter, seed, x, out, rec;
	int i;
	half_pm1 (&e_half); quarter_pp1 (&e_quarter);
	hexin ("1234567890abcdef1122334455667788aabbccddeeff00998877665544332211", &seed);

	x = seed; for (i = 0; i < STEPS; i++) { sqrt_perm (&x, &e_half, &e_quarter, &out); x = out; }
	printf ("REF sloth_out "); hexout (&x); printf ("\n");

	rec = x; for (i = 0; i < STEPS; i++) { sqrt_perm_inv (&rec, &out); rec = out; }
	printf ("REF verify_recovers_seed %s\n", eq (&rec, &seed) ? "YES" : "NO");

	{
		u256 y = seed, o; for (i = 0; i < STEPS; i++) { sqrt_perm (&y, &e_half, &e_quarter, &o); y = o; }
		printf ("REF deterministic %s\n", eq (&y, &x) ? "YES" : "NO");
	}
	{
		u256 y = seed, o; for (i = 0; i < STEPS + 1; i++) { sqrt_perm (&y, &e_half, &e_quarter, &o); y = o; }
		printf ("REF steps_matter %s\n", !eq (&y, &x) ? "YES" : "NO");
	}
	{
		u256 bad = x, o; bad.v[0] ^= 1; for (i = 0; i < STEPS; i++) { sqrt_perm_inv (&bad, &o); bad = o; }
		printf ("REF tamper_detected %s\n", !eq (&bad, &seed) ? "YES" : "NO");
	}
	return eq (&rec, &seed) ? 0 : 1;
}
