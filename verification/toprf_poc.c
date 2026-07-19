/*
 * toprf_poc.c — threshold OPRF (docs/OPRF-SPEC.md, IDEAS-BACKLOG.md §C /
 * "Password protocols" row). The single-server OPRF (step [17]) is one point of
 * compromise; a threshold OPRF Shamir-splits the server key K across n servers,
 * and any t partial evaluations combine via Lagrange-in-the-exponent to the
 * SAME output as the single-key OPRF. t-1 servers learn nothing; no server sees
 * the password (only the blinded element).
 *
 * Reuses the exact group of oprf_poc.c and drives the REAL in-tree Crypto/Sha2.c;
 * toprf_reference.py is independent. build_and_verify.sh diffs the REF lines.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

static const uint64_t P = 17592186046427ULL;
static const uint64_t Q = 8796093023213ULL;
static const uint64_t G = 4;

static uint64_t mulmod (uint64_t a, uint64_t b, uint64_t m) { return (uint64_t)(((unsigned __int128) a * b) % m); }
static uint64_t powmod (uint64_t b, uint64_t e, uint64_t m) { uint64_t r = 1; b %= m; while (e){ if (e&1) r = mulmod (r,b,m); b = mulmod (b,b,m); e >>= 1; } return r; }
static uint64_t submod (uint64_t a, uint64_t b, uint64_t m) { a %= m; b %= m; return a >= b ? a - b : m - (b - a); }
static uint64_t inv (uint64_t a, uint64_t m) { return powmod (a, m - 2, m); }

static void le64 (uint64_t x, unsigned char o[8]) { int i; for (i=0;i<8;i++) o[i]=(unsigned char)(x>>(8*i)); }
static uint64_t be64 (const unsigned char *b) { uint64_t v=0; int i; for (i=0;i<8;i++) v=(v<<8)|b[i]; return v; }
static void sha256_of (unsigned char out[32], const unsigned char *p0, int n0, const unsigned char *p1, int n1, const unsigned char *p2, int n2)
{ sha256_ctx c; sha256_begin (&c); if (n0) sha256_hash (p0,(uint_32t)n0,&c); if (n1) sha256_hash (p1,(uint_32t)n1,&c); if (n2) sha256_hash (p2,(uint_32t)n2,&c); sha256_end (out,&c); }
static uint64_t Hq (const unsigned char *pw, int n) { unsigned char h[32]; sha256_of (h,(const unsigned char*)"h2",2,pw,n,0,0); return be64 (h) % Q; }
static uint64_t H2 (const unsigned char *pw, int n) { return powmod (G, Hq (pw,n), P); }
static void oprf_out (const unsigned char *pw, int n, uint64_t U, unsigned char F[32]) { unsigned char ub[8]; le64 (U,ub); sha256_of (F,(const unsigned char*)"oprf",4,pw,n,ub,8); }

static void single (const unsigned char *pw, int n, uint64_t K, uint64_t r, unsigned char F[32])
{ uint64_t A = powmod (H2 (pw,n), r, P), B = powmod (A, K, P), U = powmod (B, inv (r, Q), P); oprf_out (pw,n,U,F); }

/* Shamir over Z_Q; shares[i] = (x=i+1, y=f(i+1)) */
static void split (uint64_t K, int t, int nn, const uint64_t *coeffs, uint64_t xs[], uint64_t ys[])
{
	int i, j;
	for (i = 0; i < nn; i++) {
		uint64_t x = (uint64_t)(i + 1), r = 0;
		for (j = t - 1; j >= 0; j--) { uint64_t a = (j == 0) ? K % Q : coeffs[j-1] % Q; r = (mulmod (r, x, Q) + a) % Q; }
		xs[i] = x; ys[i] = r;
	}
}

/* threshold eval over a t-subset (indices into xs/ys); returns blinded A too */
static void threshold (const unsigned char *pw, int n, const uint64_t xs[], const uint64_t ys[],
                       const int *sub, int t, uint64_t r, unsigned char F[32], uint64_t *Aout)
{
	uint64_t A = powmod (H2 (pw,n), r, P), B = 1;
	int a, b;
	for (a = 0; a < t; a++) {
		uint64_t num = 1, den = 1, lam, Bi;
		for (b = 0; b < t; b++) {
			if (a == b) continue;
			num = mulmod (num, submod (0, xs[sub[b]], Q), Q);      /* (0 - x_b) */
			den = mulmod (den, submod (xs[sub[a]], xs[sub[b]], Q), Q);
		}
		lam = mulmod (num, inv (den, Q), Q);
		Bi = powmod (A, ys[sub[a]], P);          /* server a returns A^{k_a} */
		B = mulmod (B, powmod (Bi, lam, P), P);  /* combine in the exponent */
	}
	{ uint64_t U = powmod (B, inv (r, Q), P); oprf_out (pw,n,U,F); }
	*Aout = A;
}

static int eq32 (const unsigned char *a, const unsigned char *b) { return memcmp (a,b,32)==0; }
static void phex (const char *l, const unsigned char *p, int n) { int i; printf ("%s", l); for (i=0;i<n;i++) printf ("%02x", p[i]); printf ("\n"); }

int main (void)
{
	const char *PWS = "correct horse battery staple";
	const unsigned char *PW = (const unsigned char *) PWS; int pwl = (int) strlen (PWS);
	uint64_t K = 0x0123456789ABCULL % Q, r = 0xABCDEF123456ULL % Q;
	uint64_t coeffs[2] = { 0x1111111111ULL, 0x2222222222ULL };
	uint64_t xs[5], ys[5], A;
	unsigned char base[32], out[32], out2[32], bad[32];

	split (K, 3, 5, coeffs, xs, ys);
	single (PW, pwl, K, r, base);
	printf ("REF single_output "); phex ("", base, 32);

	{ int sub[3] = { 0, 2, 4 }; threshold (PW, pwl, xs, ys, sub, 3, r, out, &A); }
	printf ("REF threshold_A %016llx\n", (unsigned long long) A);
	printf ("REF threshold_output "); phex ("", out, 32);
	printf ("REF threshold_matches_single %s\n", eq32 (out, base) ? "YES" : "NO");
	{ int sub[3] = { 1, 3, 4 }; threshold (PW, pwl, xs, ys, sub, 3, r, out2, &A); }
	printf ("REF any_t_subset_agrees %s\n", eq32 (out2, base) ? "YES" : "NO");
	{ int sub[2] = { 0, 1 }; threshold (PW, pwl, xs, ys, sub, 2, r, bad, &A); }
	printf ("REF below_threshold_differs %s\n", !eq32 (bad, base) ? "YES" : "NO");
	printf ("REF server_sees_only_blinded %s\n", A != H2 (PW, pwl) ? "YES" : "NO");
	return eq32 (out, base) ? 0 : 1;
}
