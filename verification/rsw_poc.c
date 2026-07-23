/*
 * rsw_poc.c — RSW time-lock puzzle (docs/DELAY-SPEC.md, IDEAS-BACKLOG.md
 * "Delay functions" row). Rivest-Shamir-Wagner 1996: opening requires
 * x^(2^T) mod N via T SEQUENTIAL squarings (unparallelizable); whoever knows
 * the factorization N = p*q has a trapdoor -- e = 2^T mod phi(N), then x^e --
 * two modexps regardless of T. The volume owner can (re)wrap instantly at
 * enrollment and then DISCARD the factors, leaving everyone (including their
 * future coerced self) the full delay. Complements Sloth (step [30]):
 * Sloth = verify-fast, RSW = create-fast.
 *
 * No standard KAT; proof = byte-identical agreement with rsw_reference.py +
 * the defining identity (trapdoor == sequential) + wrong-trapdoor divergence.
 * Same 256-bit modulus-parameterized bignum as the VSS PoCs.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct { uint64_t v[4]; } u256;

/* N = p*q, p = 2^127+0x12b7-adjacent prime, q = 2^127+0xcb003-adjacent prime */
static const u256 N   = { { 0xed720825ULL, 0x0ULL, 0x6615dULL, 0x4000000000000000ULL } };
static const u256 PHI = { { 0xed65456cULL, 0x0ULL, 0x6615cULL, 0x4000000000000000ULL } };

static int ucmp (const u256 *a, const u256 *b)
{ int i; for (i = 3; i >= 0; i--) { if (a->v[i] < b->v[i]) return -1; if (a->v[i] > b->v[i]) return 1; } return 0; }
static int uge (const u256 *a, const u256 *b) { return ucmp (a, b) >= 0; }

static void usub (const u256 *a, const u256 *b, u256 *r)
{ unsigned __int128 br = 0; int i; for (i = 0; i < 4; i++) { unsigned __int128 t = (unsigned __int128) a->v[i] - b->v[i] - br; r->v[i] = (uint64_t) t; br = (t >> 64) & 1; } }

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
static void small (uint64_t x, u256 *r) { r->v[0] = x; r->v[1] = r->v[2] = r->v[3] = 0; }
static int eq (const u256 *a, const u256 *b) { return ucmp (a, b) == 0; }


static void hexout (const u256 *a) { int i; for (i = 3; i >= 0; i--) printf ("%016llx", (unsigned long long) a->v[i]); }
static void hexin (const char *s, u256 *r)
{ int len = (int) strlen (s), i; memset (r, 0, sizeof *r);
  for (i = 0; i < len; i++) { int d = s[i] <= '9' ? s[i]-'0' : (s[i]|32)-'a'+10; int pos = (len-1-i)*4; r->v[pos>>6] |= (uint64_t) d << (pos&63); } }

#define T_STEPS 1000

static void sequential (const u256 *seed, int t, u256 *out)
{ u256 x = *seed; int i; for (i = 0; i < t; i++) mulmod (&x, &x, &N, &x); *out = x; }

static void trapdoor (const u256 *seed, const u256 *phi, u256 *out)
{
	u256 two, tt, e;
	small (2, &two); small (T_STEPS, &tt);
	powmod (&two, &tt, phi, &e);      /* e = 2^T mod phi */
	powmod (seed, &e, &N, out);       /* x^e mod N */
}

int main (void)
{
	u256 seed, slow, fast;
	hexin ("1234567890abcdef1122334455667788aabbccddeeff00998877665544332211", &seed);
	/* reduce seed mod N once (seed < 2^256 may exceed N) */
	{ u256 one = { { 1, 0, 0, 0 } }; mulmod (&seed, &one, &N, &seed); }

	sequential (&seed, T_STEPS, &slow);
	printf ("REF rsw_out "); hexout (&slow); printf ("\n");

	trapdoor (&seed, &PHI, &fast);
	printf ("REF trapdoor_matches_sequential %s\n", eq (&fast, &slow) ? "YES" : "NO");

	{ u256 again; sequential (&seed, T_STEPS, &again); printf ("REF deterministic %s\n", eq (&again, &slow) ? "YES" : "NO"); }
	{ u256 more; sequential (&seed, T_STEPS + 1, &more); printf ("REF steps_matter %s\n", !eq (&more, &slow) ? "YES" : "NO"); }
	{
		u256 badphi = PHI, wrong, two = { { 2, 0, 0, 0 } };
		usub (&badphi, &two, &badphi);
		trapdoor (&seed, &badphi, &wrong);
		printf ("REF wrong_trapdoor_detected %s\n", !eq (&wrong, &slow) ? "YES" : "NO");
	}
	return eq (&fast, &slow) ? 0 : 1;
}
