/*
 * ed25519_hacl_xcheck.c — THIRD-PARTY oracle for the from-scratch edwards25519 group, using HACL*.
 *
 * WHY (anchor audit). Step [39] (`netshare_ed25519_poc.c`) carries an OFFICIAL anchor — the RFC 8032
 * Section 7.1 public-key KAT. That is real, and it passes. But it only exercises ONE operation:
 * `secret_to_public`, i.e. scalar multiplication of the FIXED BASEPOINT.
 *
 * The McCallum-Relyea exchange that step [39] exists to support does not just multiply the basepoint. It
 * multiplies ARBITRARY points (the peer's public element) and ADDS points. Those operations are not
 * covered by Section 7.1 at all. That is the same shape as the defect found at step [94]: an official
 * vector anchoring one layer (ristretto255 encoding, RFC 9496 A.1) while the layer that actually mattered
 * (hash-to-group, A.2) went unchecked and turned out to be wrong.
 *
 * So this harness cross-checks the from-scratch group against HACL* — formally verified (F*), and code
 * this project did not write — on exactly the unanchored operations:
 *   - arbitrary-point scalar multiplication  (pt_mul on a non-basepoint)
 *   - point addition                          (pt_add)
 *   - point negation + P + (-P) == identity
 *   - the MR-shaped composite: k2*(k1*B) == k1*(k2*B)
 * plus basepoint agreement as a sanity anchor.
 *
 * Anchor class: THIRD-PARTY (see docs/VERIFICATION-ANCHORS.md). VERIFICATION-only; HACL* is never linked
 * into the product. Nothing here changes step [39]'s official KAT — this ADDS coverage beneath it.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Pull in the from-scratch group (its helpers are static). Rename its main out of the way. */
#define main netshare_ed25519_poc_main_unused
#include "netshare_ed25519_poc.c"
#undef main

#include "Hacl_EC_Ed25519.h"

static void tohex (const unsigned char *p, int n, char *o)
{ int i; for (i = 0; i < n; i++) sprintf (o + 2 * i, "%02x", p[i]); }

/* u256 (4 x uint64 little-endian limbs) -> 32-byte little-endian scalar for HACL. */
static void u256_to_le32 (const u256 *k, uint8_t out[32])
{
	int i, j;
	for (i = 0; i < 4; i++)
		for (j = 0; j < 8; j++)
			out[i * 8 + j] = (uint8_t) ((k->v[i] >> (8 * j)) & 0xff);
}

static int g_fail = 0;
static void ck (const char *label, const unsigned char *a, const unsigned char *b)
{
	char ha[65], hb[65];
	tohex (a, 32, ha); tohex (b, 32, hb);
	if (memcmp (a, b, 32) == 0)
		printf ("    %-52s MATCH  %s\n", label, ha);
	else { printf ("    %-52s MISMATCH\n      scratch %s\n      hacl    %s\n", label, ha, hb); g_fail = 1; }
}

/* Scalars chosen to exercise varied bit patterns (not secrets — this is a KAT harness). */
static const u256 K1 = { { 0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x00ff00ff00ff00ffULL, 0x0f0f0f0f0f0f0f0fULL } };
static const u256 K2 = { { 0xdeadbeefcafebabeULL, 0x0000000000000007ULL, 0xffffffffffffffffULL, 0x0102030405060708ULL } };

int main (void)
{
	unsigned char s_out[32], h_out[32];
	uint8_t k1b[32], k2b[32];
	uint64_t hB[20], hP[20], hQ[20], hR[20], hT[20];
	pt sB, sP, sQ, sR;

	u256_to_le32 (&K1, k1b);
	u256_to_le32 (&K2, k2b);

	printf ("Ed25519 group: from-scratch (step [39]) vs HACL* — operations RFC 8032 S7.1 does NOT cover\n");

	/* (0) basepoint — sanity; this layer IS covered by the official KAT */
	pt_base (&sB);            pt_compress (&sB, s_out);
	Hacl_EC_Ed25519_mk_base_point (hB); Hacl_EC_Ed25519_point_compress (hB, h_out);
	ck ("basepoint B (sanity, already RFC-anchored)", s_out, h_out);

	/* (1) basepoint scalar-mult — the operation S7.1 covers */
	pt_mul (&K1, &sB, &sP);   pt_compress (&sP, s_out);
	Hacl_EC_Ed25519_point_mul (k1b, hB, hP); Hacl_EC_Ed25519_point_compress (hP, h_out);
	ck ("k1*B  (basepoint mult)", s_out, h_out);

	/* (2) ARBITRARY-POINT scalar-mult — UNANCHORED by S7.1; MR depends on it */
	pt_mul (&K2, &sP, &sQ);   pt_compress (&sQ, s_out);
	Hacl_EC_Ed25519_point_mul (k2b, hP, hQ); Hacl_EC_Ed25519_point_compress (hQ, h_out);
	ck ("k2*(k1*B)  [arbitrary-point mult]", s_out, h_out);

	/* (3) POINT ADDITION — UNANCHORED by S7.1 */
	{
		pt sK2B; uint64_t hK2B[20];
		pt_mul (&K2, &sB, &sK2B);
		Hacl_EC_Ed25519_point_mul (k2b, hB, hK2B);
		pt_add (&sP, &sK2B, &sR); pt_compress (&sR, s_out);
		Hacl_EC_Ed25519_point_add (hP, hK2B, hR); Hacl_EC_Ed25519_point_compress (hR, h_out);
		ck ("(k1*B) + (k2*B)  [point addition]", s_out, h_out);
	}

	/* (4) NEGATION — UNANCHORED by S7.1 */
	{
		pt sN; uint64_t hN[20];
		pt_neg (&sP, &sN); pt_compress (&sN, s_out);
		Hacl_EC_Ed25519_point_negate (hP, hN); Hacl_EC_Ed25519_point_compress (hN, h_out);
		ck ("-(k1*B)  [negation]", s_out, h_out);

		/* P + (-P) must be the identity in both */
		pt sI; uint64_t hI[20], hInf[20];
		pt_add (&sP, &sN, &sI); pt_compress (&sI, s_out);
		Hacl_EC_Ed25519_point_add (hP, hN, hI); Hacl_EC_Ed25519_point_compress (hI, h_out);
		ck ("P + (-P)  [== identity]", s_out, h_out);
		Hacl_EC_Ed25519_mk_point_at_inf (hInf);
		printf ("    %-52s %s\n", "HACL* agrees it is the point at infinity",
		        Hacl_EC_Ed25519_point_eq (hI, hInf) ? "YES" : "NO");
		if (!Hacl_EC_Ed25519_point_eq (hI, hInf)) g_fail = 1;
	}

	/* (5) the MR-shaped commutativity the exchange relies on: k2*(k1*B) == k1*(k2*B) */
	{
		pt sK2B, sC; uint64_t hK2B[20], hC[20];
		pt_mul (&K2, &sB, &sK2B); pt_mul (&K1, &sK2B, &sC); pt_compress (&sC, s_out);
		Hacl_EC_Ed25519_point_mul (k2b, hB, hK2B);
		Hacl_EC_Ed25519_point_mul (k1b, hK2B, hC); Hacl_EC_Ed25519_point_compress (hC, h_out);
		ck ("k1*(k2*B)  [MR commutativity, vs HACL]", s_out, h_out);

		/* and it must equal k2*(k1*B) computed above, within the from-scratch code */
		unsigned char q_out[32];
		pt_compress (&sQ, q_out);
		ck ("k1*(k2*B) == k2*(k1*B)  [MR identity]", s_out, q_out);
	}

	(void) hT;
	if (g_fail) { printf ("ED25519 HACL XCHECK: MISMATCH\n"); return 1; }
	printf ("ED25519 HACL XCHECK: from-scratch group == HACL* on all operations (incl. the ones S7.1 misses)\n");
	return 0;
}
