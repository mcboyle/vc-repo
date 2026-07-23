/*
 * oprf_poc.c — proof-of-concept for OPRF password hardening (docs/OPRF-SPEC.md, IDEAS-BACKLOG.md §C).
 *
 * A 2HashDH / CFRG DH-OPRF: the derived key depends on the password AND a secret held by a rate-limited
 * server, and the server learns neither the password nor the output — so a stolen disk cannot be
 * brute-forced offline. See oprf_reference.py for the protocol. This drives the REAL in-tree
 * Crypto/Sha2.c; the Python reference is independent. build_and_verify.sh diffs the REF lines.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

static const uint64_t P = 17592186046427ULL;
static const uint64_t Q = 8796093023213ULL;   /* prime order of g */
static const uint64_t G = 4;

static uint64_t mulmod (uint64_t a, uint64_t b, uint64_t m)
{ return (uint64_t) (((unsigned __int128) a * b) % m); }
static uint64_t powmod (uint64_t base, uint64_t exp, uint64_t m)
{ uint64_t r = 1; base %= m; while (exp){ if (exp & 1) r = mulmod (r, base, m); base = mulmod (base, base, m); exp >>= 1; } return r; }

static void le64 (uint64_t x, unsigned char o[8]) { int i; for (i=0;i<8;i++) o[i]=(unsigned char)(x>>(8*i)); }
static uint64_t be64 (const unsigned char *b) { uint64_t v=0; int i; for (i=0;i<8;i++) v=(v<<8)|b[i]; return v; }

static void sha256_of (unsigned char out[32], const unsigned char *p0, int n0,
                       const unsigned char *p1, int n1, const unsigned char *p2, int n2)
{
	sha256_ctx c; sha256_begin (&c);
	if (n0) sha256_hash (p0, (uint_32t) n0, &c);
	if (n1) sha256_hash (p1, (uint_32t) n1, &c);
	if (n2) sha256_hash (p2, (uint_32t) n2, &c);
	sha256_end (out, &c);
}

static uint64_t Hq (const unsigned char *pw, int pwLen)
{
	unsigned char h[32];
	sha256_of (h, (const unsigned char *) "h2", 2, pw, pwLen, 0, 0);
	return be64 (h) % Q;
}
static uint64_t H2 (const unsigned char *pw, int pwLen) { return powmod (G, Hq (pw, pwLen), P); }

static void oprf_out (const unsigned char *pw, int pwLen, uint64_t U, unsigned char F[32])
{
	unsigned char ub[8]; le64 (U, ub);
	sha256_of (F, (const unsigned char *) "oprf", 4, pw, pwLen, ub, 8);
}

/* returns blinded A via *Aout and the OPRF output F */
static void evaluate (const unsigned char *pw, int pwLen, uint64_t k, uint64_t r,
                      uint64_t *Aout, unsigned char F[32])
{
	uint64_t A = powmod (H2 (pw, pwLen), r, P);     /* client blinds */
	uint64_t B = powmod (A, k, P);                  /* server evaluates (sees only A) */
	uint64_t U = powmod (B, powmod (r, Q - 2, Q), P); /* client unblinds: B^(1/r) = H2(pw)^k */
	*Aout = A;
	oprf_out (pw, pwLen, U, F);
}

static void phex (const char *l, const unsigned char *p, int n)
{ int i; printf ("%s", l); for (i=0;i<n;i++) printf ("%02x", p[i]); printf ("\n"); }

int main (void)
{
	const char *PWS = "correct horse battery staple";
	const unsigned char *PW = (const unsigned char *) PWS; int pwl = (int) strlen (PWS);
	uint64_t K = 0x0123456789ABCULL % Q, R1 = 0xABCDEF123456ULL % Q, R2 = 0x0F1E2D3C4B5AULL % Q, KW = 0x9999999999ULL % Q;
	uint64_t A1, A2, Aw, Ap;
	unsigned char F1[32], F2[32], Fw[32], Fp[32];

	evaluate (PW, pwl, K, R1, &A1, F1);
	phex ("REF oprf_output = ", F1, 32);

	evaluate (PW, pwl, K, R2, &A2, F2);
	printf ("REF output independent of blind (F(r1)==F(r2)) = %s\n", memcmp (F1, F2, 32) == 0 ? "YES" : "NO");
	printf ("REF blinded messages differ (A(r1)!=A(r2)) = %s\n", A1 != A2 ? "YES" : "NO");
	printf ("REF server sees blinded A != H2(pw) = %s\n", A1 != H2 (PW, pwl) ? "YES" : "NO");

	evaluate (PW, pwl, KW, R1, &Aw, Fw);
	printf ("REF wrong server key -> different output = %s\n", memcmp (Fw, F1, 32) != 0 ? "YES" : "NO");

	{
		const char *PW2 = "correct horse battery stapl3";
		evaluate ((const unsigned char *) PW2, (int) strlen (PW2), K, R1, &Ap, Fp);
		printf ("REF different password -> different output = %s\n", memcmp (Fp, F1, 32) != 0 ? "YES" : "NO");
	}
	return 0;
}
