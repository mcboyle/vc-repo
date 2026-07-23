/*
 * voprf_ristretto_poc.c — VERIFIABLE OPRF (VOPRF) with a DLEQ proof over ristretto255
 * (build_and_verify.sh step [47]; docs/OPRF-SPEC.md). Extends the step-[43] OPRF: in verifiable mode
 * the server commits to a public key pk = k*G and, with each evaluation EE = k*BE, proves in zero
 * knowledge that the SAME k relates (G, pk) and (BE, EE) -- a Chaum-Pedersen / DLEQ proof. The client
 * verifies the proof before finalizing, so a server that swaps in a different key (or a MITM that
 * tampers with EE) is caught, not silently trusted.
 *
 * Reuses the proven step-[43] ristretto255 group (RFC 9496/9497), over the REAL in-tree Sha2.c.
 * Proven: (1) RFC 9496 basepoint KAT anchors the group; (2) the proof (c, s) + pk are diffed
 * byte-for-byte vs voprf_ristretto_reference.py (fixed proof nonce, so deterministic); (3) a valid
 * proof verifies, a tampered EE is rejected, and a wrong committed key is rejected. The exact RFC 9497
 * verifiable-mode transcript (batched composites) stays real-build; this is a faithful single-element
 * DLEQ, proven two-way.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"
typedef struct { uint64_t v[4]; } u256;

static const u256 P  = { { 0xffffffffffffffedULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL } };
static const u256 L  = { { 0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL, 0x0000000000000000ULL, 0x1000000000000000ULL } };
static const u256 D  = { { 0x75eb4dca135978a3ULL, 0x00700a4d4141d8abULL, 0x8cc740797779e898ULL, 0x52036cee2b6ffe73ULL } };
static const u256 SQRT_M1           = { { 0xc4ee1b274a0ea0b0ULL, 0x2f431806ad2fe478ULL, 0x2b4d00993dfbd7a7ULL, 0x2b8324804fc1df0bULL } };
static const u256 INVSQRT_A_MINUS_D = { { 0x99c8fdaa805d40eaULL, 0x9d2f16175a4172beULL, 0x16c27b91fe01d840ULL, 0x786c8905cfaffca2ULL } };
static const u256 ONE_MINUS_D_SQ    = { { 0xe27c09c1945fc176ULL, 0x2c81a138cd5e350fULL, 0x9994abddbe70dfe4ULL, 0x029072a8b2b3e0d7ULL } };
static const u256 D_MINUS_ONE_SQ    = { { 0x31ad5aaa44ed4d20ULL, 0xd29e4a2cb01e1999ULL, 0x4cdcd32f529b4eebULL, 0x5968b37af66c2241ULL } };
static const u256 SQRT_AD_MINUS_ONE = { { 0x8168095fb684d1d2ULL, 0x506271f3e487ab42ULL, 0xf0c30336ce0a2e02ULL, 0x4896ce40d47cb753ULL } };
static const u256 BX = { { 0xc9562d608f25d51aULL, 0x692cc7609525a7b2ULL, 0xc0a4e231fdd6dc5cULL, 0x216936d3cd6e53feULL } };
static const u256 BY = { { 0x6666666666666658ULL, 0x6666666666666666ULL, 0x6666666666666666ULL, 0x6666666666666666ULL } };

/* ---- field arithmetic mod m (from step [39], proven) ---- */
static int ucmp (const u256 *a, const u256 *b)
{ int i; for (i = 3; i >= 0; i--) { if (a->v[i] < b->v[i]) return -1; if (a->v[i] > b->v[i]) return 1; } return 0; }
static int uge (const u256 *a, const u256 *b) { return ucmp (a, b) >= 0; }

static void reduce512 (const uint64_t prod[8], const u256 *m, u256 *r)
{
	uint64_t rem[5]; int bit, k;
	memset (rem, 0, sizeof rem);
	for (bit = 511; bit >= 0; bit--) {
		uint64_t carry = (prod[bit >> 6] >> (bit & 63)) & 1, nc;
		for (k = 0; k < 5; k++) { nc = rem[k] >> 63; rem[k] = (rem[k] << 1) | carry; carry = nc; }
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
	for (i = 0; i < 4; i++) { c = 0;
		for (j = 0; j < 4; j++) { unsigned __int128 t = (unsigned __int128) a->v[i] * b->v[j] + prod[i + j] + c; prod[i + j] = (uint64_t) t; c = t >> 64; }
		prod[i + 4] += (uint64_t) c; }
	reduce512 (prod, m, r);
}
static void addmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 c = 0; int i; u256 t;
	for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) a->v[i] + b->v[i] + c; t.v[i] = (uint64_t) s; c = s >> 64; }
	if (c || uge (&t, m)) { unsigned __int128 br = 0; for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) t.v[i] - m->v[i] - br; t.v[i] = (uint64_t) s; br = (s >> 64) & 1; } }
	*r = t;
}
static void submod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 br = 0, c = 0; int i; u256 t;
	for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) a->v[i] - b->v[i] - br; t.v[i] = (uint64_t) s; br = (s >> 64) & 1; }
	if (br) for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) t.v[i] + m->v[i] + c; t.v[i] = (uint64_t) s; c = s >> 64; }
	*r = t;
}
static void powmod (const u256 *base, const u256 *exp, const u256 *m, u256 *r)
{
	u256 res = { { 1, 0, 0, 0 } }, b = *base; int i;
	for (i = 255; i >= 0; i--) { mulmod (&res, &res, m, &res); if ((exp->v[i >> 6] >> (i & 63)) & 1) mulmod (&res, &b, m, &res); }
	*r = res;
}

/* ---- field helpers mod p ---- */
static void fe_mul (const u256 *a, const u256 *b, u256 *r) { mulmod (a, b, &P, r); }
static void fe_add (const u256 *a, const u256 *b, u256 *r) { addmod (a, b, &P, r); }
static void fe_sub (const u256 *a, const u256 *b, u256 *r) { submod (a, b, &P, r); }
static void fe_set (u256 *r, uint64_t x) { r->v[0] = x; r->v[1] = r->v[2] = r->v[3] = 0; }
static int  fe_is_neg (const u256 *a) { return (int) (a->v[0] & 1); }       /* low bit (a is reduced) */
static int  fe_eq (const u256 *a, const u256 *b) { return ucmp (a, b) == 0; }
static void fe_neg (const u256 *a, u256 *r) { u256 z; fe_set (&z, 0); fe_sub (&z, a, r); }
static void fe_abs (const u256 *a, u256 *r) { if (fe_is_neg (a)) fe_neg (a, r); else *r = *a; }
static void fe_inv (const u256 *a, u256 *r) { u256 e = P; e.v[0] -= 2; powmod (a, &e, &P, r); }

/* sqrt_ratio_i(u,v) per RFC 9496: (*wasSquare, r = principal sqrt of u/v or of SQRT_M1*u/v). */
static int fe_sqrt_ratio_i (const u256 *u, const u256 *v, u256 *out)
{
	u256 v2, v3, v7, r, chk, uv, negu, negui, rp, e;
	int correct, flipped, flipped_i, wasSquare;
	fe_mul (v, v, &v2); fe_mul (&v2, v, &v3); fe_mul (&v3, &v3, &v7); fe_mul (&v7, v, &v7);
	fe_mul (u, &v7, &uv);
	/* e = (p-5)/8 : p-5 then shift right 3 (p.v[0] = ...fed >= 5, no borrow) */
	{ u256 pm5 = P; int i; uint64_t carry = 0; pm5.v[0] -= 5;
	  for (i = 3; i >= 0; i--) { uint64_t nx = pm5.v[i] & 7; pm5.v[i] = (pm5.v[i] >> 3) | (carry << 61); carry = nx; } e = pm5; }
	powmod (&uv, &e, &P, &r);
	fe_mul (u, &v3, &v3); fe_mul (&v3, &r, &r);                 /* r = u*v3 * (u v7)^((p-5)/8) */
	fe_mul (v, &r, &chk); fe_mul (&chk, &r, &chk);              /* chk = v r^2 */
	correct = fe_eq (&chk, u);
	fe_neg (u, &negu); flipped = fe_eq (&chk, &negu);
	fe_mul (&negu, &SQRT_M1, &negui); flipped_i = fe_eq (&chk, &negui);
	fe_mul (&r, &SQRT_M1, &rp);
	if (flipped || flipped_i) r = rp;
	fe_abs (&r, &r);
	wasSquare = correct || flipped;
	*out = r;
	return wasSquare;
}

/* ---- ristretto point = edwards extended (X:Y:Z:T), a=-1 ---- */
typedef struct { u256 X, Y, Z, T; } pt;
static void pt_identity (pt *r) { fe_set (&r->X, 0); fe_set (&r->Y, 1); fe_set (&r->Z, 1); fe_set (&r->T, 0); }
static void pt_base (pt *r) { r->X = BX; r->Y = BY; fe_set (&r->Z, 1); fe_mul (&BX, &BY, &r->T); }
static void pt_add (const pt *p1, const pt *p2, pt *r)
{
	u256 A, B, C, Dd, E, F, G, H, t1, t2, d2;
	fe_sub (&p1->Y, &p1->X, &t1); fe_sub (&p2->Y, &p2->X, &t2); fe_mul (&t1, &t2, &A);
	fe_add (&p1->Y, &p1->X, &t1); fe_add (&p2->Y, &p2->X, &t2); fe_mul (&t1, &t2, &B);
	fe_add (&D, &D, &d2); fe_mul (&p1->T, &p2->T, &t1); fe_mul (&t1, &d2, &C);
	fe_mul (&p1->Z, &p2->Z, &t1); fe_add (&t1, &t1, &Dd);
	fe_sub (&B, &A, &E); fe_sub (&Dd, &C, &F); fe_add (&Dd, &C, &G); fe_add (&B, &A, &H);
	fe_mul (&E, &F, &r->X); fe_mul (&G, &H, &r->Y); fe_mul (&E, &H, &r->T); fe_mul (&F, &G, &r->Z);
}
/* scalar mult by k (a 256-bit scalar < L), MSB-first double-and-add */
static void pt_mul (const u256 *k, const pt *base, pt *r)
{
	pt acc; int i; pt_identity (&acc);
	for (i = 255; i >= 0; i--) { pt t; pt_add (&acc, &acc, &t); acc = t; if ((k->v[i >> 6] >> (i & 63)) & 1) { pt_add (&acc, base, &t); acc = t; } }
	*r = acc;
}

/* ristretto255 encode (RFC 9496 4.3.2) */
static void ristretto_encode (const pt *pnt, unsigned char out[32])
{
	u256 u1, u2, u2sq, invsqrt, D1, D2, Zinv, ix0, iy0, ench, tmp, Xn, Yn, Dn, s, ZmY; int rotate, i;
	fe_add (&pnt->Z, &pnt->Y, &tmp); fe_sub (&pnt->Z, &pnt->Y, &u1); fe_mul (&tmp, &u1, &u1);
	fe_mul (&pnt->X, &pnt->Y, &u2);
	fe_mul (&u2, &u2, &u2sq); fe_mul (&u1, &u2sq, &tmp);
	{ u256 one; fe_set (&one, 1); fe_sqrt_ratio_i (&one, &tmp, &invsqrt); }
	fe_mul (&invsqrt, &u1, &D1); fe_mul (&invsqrt, &u2, &D2);
	fe_mul (&D1, &D2, &Zinv); fe_mul (&Zinv, &pnt->T, &Zinv);
	fe_mul (&pnt->X, &SQRT_M1, &ix0); fe_mul (&pnt->Y, &SQRT_M1, &iy0);
	fe_mul (&D1, &INVSQRT_A_MINUS_D, &ench);
	fe_mul (&pnt->T, &Zinv, &tmp); rotate = fe_is_neg (&tmp);
	Xn = rotate ? iy0 : pnt->X;
	Yn = rotate ? ix0 : pnt->Y;
	Dn = rotate ? ench : D2;
	fe_mul (&Xn, &Zinv, &tmp); if (fe_is_neg (&tmp)) { u256 ny; fe_neg (&Yn, &ny); Yn = ny; }
	fe_sub (&pnt->Z, &Yn, &ZmY); fe_mul (&Dn, &ZmY, &s); fe_abs (&s, &s);
	for (i = 0; i < 32; i++) out[i] = (unsigned char) (s.v[i >> 3] >> ((i & 7) * 8));
}

/* Elligator2 map for ristretto (RFC 9496 4.3.4): field element -> point */
static void ristretto_map (const u256 *t, pt *out)
{
	u256 r, u, v, s, sp, c, N, w0, w1, w2, w3, tmp, one, rt; int wasSq;
	fe_set (&one, 1);
	fe_mul (t, t, &r); fe_mul (&SQRT_M1, &r, &r);              /* r = i * t^2 */
	fe_add (&r, &one, &u); fe_mul (&u, &ONE_MINUS_D_SQ, &u);   /* u = (r+1)(1-d^2) */
	fe_mul (&r, &D, &tmp); fe_neg (&tmp, &tmp); fe_sub (&tmp, &one, &tmp);   /* -1 - r*d */
	fe_add (&r, &D, &rt); fe_mul (&tmp, &rt, &v);              /* v = (-1-r*d)(r+d) */
	wasSq = fe_sqrt_ratio_i (&u, &v, &s);
	fe_mul (&s, t, &sp); fe_abs (&sp, &sp); fe_neg (&sp, &sp); /* s' = -|s*t| */
	if (!wasSq) s = sp;
	if (wasSq) fe_neg (&one, &c); else c = r;                  /* c = -1 or r */
	fe_sub (&r, &one, &tmp); fe_mul (&c, &tmp, &tmp); fe_mul (&tmp, &D_MINUS_ONE_SQ, &tmp);
	fe_sub (&tmp, &v, &N);                                     /* N = c(r-1)(d-1)^2 - v */
	fe_add (&s, &s, &w0); fe_mul (&w0, &v, &w0);               /* w0 = 2 s v */
	fe_mul (&N, &SQRT_AD_MINUS_ONE, &w1);                      /* w1 = N sqrt(ad-1) */
	fe_mul (&s, &s, &tmp); fe_sub (&one, &tmp, &w2);           /* w2 = 1 - s^2 */
	fe_add (&one, &tmp, &w3);                                  /* w3 = 1 + s^2 */
	fe_mul (&w0, &w3, &out->X); fe_mul (&w2, &w1, &out->Y); fe_mul (&w1, &w3, &out->Z); fe_mul (&w0, &w2, &out->T);
}

/* expand_message_xmd(SHA-512) (RFC 9380 5.3.1), length 64 (ell = 1) */
static void expand_xmd64 (const unsigned char *msg, int msgLen, const unsigned char *dst, int dstLen, unsigned char out[64])
{
	unsigned char buf[128 + 512 + 3 + 64], b0[64], b1[64];
	int n = 0, i;
	for (i = 0; i < 128; i++) buf[n++] = 0;                    /* Z_pad (SHA-512 block = 128) */
	for (i = 0; i < msgLen; i++) buf[n++] = msg[i];
	buf[n++] = 0; buf[n++] = 64;                               /* I2OSP(64,2) */
	buf[n++] = 0;                                              /* I2OSP(0,1) */
	for (i = 0; i < dstLen; i++) buf[n++] = dst[i];
	buf[n++] = (unsigned char) dstLen;                        /* DST_prime tail */
	sha512 (b0, buf, (uint_64t) n);
	{ unsigned char t[64 + 1 + 512 + 1]; int m = 0;
	  for (i = 0; i < 64; i++) t[m++] = b0[i];
	  t[m++] = 1;
	  for (i = 0; i < dstLen; i++) t[m++] = dst[i];
	  t[m++] = (unsigned char) dstLen;
	  sha512 (b1, t, (uint_64t) m); }
	memcpy (out, b1, 64);
}

static const unsigned char DST_G[] = "HashToGroup-OPRFV1-\x00-ristretto255-SHA512";
#define DST_G_LEN 40   /* 39 chars incl the embedded NUL + no trailing NUL counted */

static void load_le (const unsigned char *b, u256 *r) { int i; memset (r, 0, sizeof *r); for (i = 0; i < 32; i++) r->v[i >> 3] |= (uint64_t) b[i] << ((i & 7) * 8); }

static void hash_to_group (const unsigned char *msg, int msgLen, pt *out)
{
	unsigned char uni[64]; u256 r1, r2; pt P1, P2;
	expand_xmd64 (msg, msgLen, DST_G, DST_G_LEN, uni);
	load_le (uni, &r1);            reduce512 ((uint64_t[8]){ r1.v[0], r1.v[1], r1.v[2], r1.v[3], 0,0,0,0 }, &P, &r1);
	load_le (uni + 32, &r2);       reduce512 ((uint64_t[8]){ r2.v[0], r2.v[1], r2.v[2], r2.v[3], 0,0,0,0 }, &P, &r2);
	ristretto_map (&r1, &P1); ristretto_map (&r2, &P2);
	pt_add (&P1, &P2, out);
}

static void inv_mod_L (const u256 *a, u256 *r) { u256 e = L; e.v[0] -= 2; powmod (a, &e, &L, r); }

/* Finalize: SHA-512( I2OSP(len(input),2) || input || I2OSP(32,2) || enc || "Finalize" ) */
static void oprf_finalize (const unsigned char *input, int inLen, const unsigned char enc[32], unsigned char out[64])
{
	unsigned char buf[2 + 512 + 2 + 32 + 8]; int n = 0, i;
	buf[n++] = (unsigned char) (inLen >> 8); buf[n++] = (unsigned char) inLen;
	for (i = 0; i < inLen; i++) buf[n++] = input[i];
	buf[n++] = 0; buf[n++] = 32;
	for (i = 0; i < 32; i++) buf[n++] = enc[i];
	memcpy (buf + n, "Finalize", 8); n += 8;
	sha512 (out, buf, (uint_64t) n);
}

static void phex (const char *label, const unsigned char *p, int n) { int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

/* ---- scalar field Z_L ---- */
static void sc_mul (const u256 *a, const u256 *b, u256 *r) { mulmod (a, b, &L, r); }
static void sc_sub (const u256 *a, const u256 *b, u256 *r) { submod (a, b, &L, r); }

/* challenge c = reduce_mod_L( SHA-512("VOPRF-DLEQ" || enc(G)||enc(pk)||enc(BE)||enc(EE)||enc(a1)||enc(a2)) ) */
static void dleq_challenge (const unsigned char g[32], const unsigned char pk[32], const unsigned char be[32],
                            const unsigned char ee[32], const unsigned char a1[32], const unsigned char a2[32], u256 *out)
{
	unsigned char buf[10 + 6*32], h[64]; int n = 0, i;
	memcpy (buf + n, "VOPRF-DLEQ", 10); n += 10;
	memcpy (buf + n, g, 32);  n += 32; memcpy (buf + n, pk, 32); n += 32; memcpy (buf + n, be, 32); n += 32;
	memcpy (buf + n, ee, 32); n += 32; memcpy (buf + n, a1, 32); n += 32; memcpy (buf + n, a2, 32); n += 32;
	sha512 (h, buf, (uint_64t) n);
	{ uint64_t limbs[8]; for (i = 0; i < 8; i++) limbs[i] = 0;
	  for (i = 0; i < 64; i++) limbs[i >> 3] |= (uint64_t) h[i] << ((i & 7) * 8);
	  reduce512 (limbs, &L, out); }
}

/* GenerateProof: a1=rr*G, a2=rr*BE, c=challenge, s=rr-c*k mod L. */
static void dleq_prove (const u256 *k, const u256 *rr, const pt *G, const pt *pk, const pt *BE, const pt *EE, u256 *c, u256 *s)
{
	pt a1, a2; unsigned char eg[32], epk[32], ebe[32], eee[32], ea1[32], ea2[32]; u256 ck;
	pt_mul (rr, G, &a1); pt_mul (rr, BE, &a2);
	ristretto_encode (G, eg); ristretto_encode (pk, epk); ristretto_encode (BE, ebe);
	ristretto_encode (EE, eee); ristretto_encode (&a1, ea1); ristretto_encode (&a2, ea2);
	dleq_challenge (eg, epk, ebe, eee, ea1, ea2, c);
	sc_mul (c, k, &ck); sc_sub (rr, &ck, s);
}

/* VerifyProof: a1=s*G+c*pk, a2=s*BE+c*EE, recompute challenge, compare. */
static int dleq_verify (const pt *G, const pt *pk, const pt *BE, const pt *EE, const u256 *c, const u256 *s)
{
	pt sG, cpk, sBE, cEE, a1, a2; unsigned char eg[32], epk[32], ebe[32], eee[32], ea1[32], ea2[32]; u256 cc;
	pt_mul (s, G, &sG); pt_mul (c, pk, &cpk); pt_add (&sG, &cpk, &a1);
	pt_mul (s, BE, &sBE); pt_mul (c, EE, &cEE); pt_add (&sBE, &cEE, &a2);
	ristretto_encode (G, eg); ristretto_encode (pk, epk); ristretto_encode (BE, ebe);
	ristretto_encode (EE, eee); ristretto_encode (&a1, ea1); ristretto_encode (&a2, ea2);
	dleq_challenge (eg, epk, ebe, eee, ea1, ea2, &cc);
	return ucmp (&cc, c) == 0;
}

int main (void)
{
	static const char *mult[5] = {
		"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
		"6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
		"94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
		"da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
		"e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e" };
	pt G, acc; unsigned char enc[32]; int i, katok = 1;
	pt_base (&G); pt_identity (&acc);
	for (i = 1; i <= 5; i++) { char got[65]; int j; pt t; pt_add (&acc, &G, &t); acc = t;
		ristretto_encode (&acc, enc); for (j = 0; j < 32; j++) sprintf (got + 2*j, "%02x", enc[j]);
		if (strcmp (got, mult[i-1]) != 0) katok = 0; }

	{
		u256 k  = { { 0x11223344556677ULL, 0x8899001122334455ULL, 0x6677889900112233ULL, 0x0abbccdd12345678ULL } };
		u256 r  = { { 0x0011223344556677ULL, 0x8899aabbccddeeffULL, 0x1122334455667788ULL, 0x00fedcba98765432ULL } };
		u256 rr = { { 0xa5a5a5a5a5a5a5a5ULL, 0x5a5a5a5a5a5a5a5aULL, 0x0102030405060708ULL, 0x00c0ffeec0ffee00ULL } };
		const unsigned char input[] = "test input"; int inLen = 10;
		pt pk, Pin, BE, EE; u256 c, s; unsigned char epk[32], sc[32], ss[32]; int j;

		pt_mul (&k, &G, &pk);                                    /* server public key pk = k*G */
		hash_to_group (input, inLen, &Pin);
		pt_mul (&r, &Pin, &BE);                                  /* client blinds */
		pt_mul (&k, &BE, &EE);                                   /* server evaluates */
		dleq_prove (&k, &rr, &G, &pk, &BE, &EE, &c, &s);         /* server proves */

		ristretto_encode (&pk, epk);
		for (j = 0; j < 32; j++) { sc[j] = (unsigned char) (c.v[j >> 3] >> ((j & 7) * 8)); ss[j] = (unsigned char) (s.v[j >> 3] >> ((j & 7) * 8)); }
		phex ("REF voprf pk = ", epk, 32);
		phex ("REF voprf proof_c = ", sc, 32);
		phex ("REF voprf proof_s = ", ss, 32);

		printf ("voprf valid proof verifies = %s\n", dleq_verify (&G, &pk, &BE, &EE, &c, &s) ? "YES" : "NO");
		/* tampered EE rejected */
		{ pt EEbad; pt_add (&EE, &G, &EEbad);
		  printf ("voprf tampered EE rejected = %s\n", !dleq_verify (&G, &pk, &BE, &EEbad, &c, &s) ? "YES" : "NO"); }
		/* wrong committed key rejected */
		{ pt pkBad; u256 kb = k; kb.v[0] ^= 1; pt_mul (&kb, &G, &pkBad);
		  printf ("voprf wrong committed key rejected = %s\n", !dleq_verify (&G, &pkBad, &BE, &EE, &c, &s) ? "YES" : "NO"); }
	}

	printf ("ristretto255 basepoint KAT (RFC 9496) = %s\n", katok ? "YES" : "NO");
	return katok ? 0 : 1;
}
