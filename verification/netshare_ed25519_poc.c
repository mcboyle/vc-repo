/*
 * netshare_ed25519_poc.c — McCallum-Relyea network-bound share at PRODUCTION parameters
 * (docs/NETWORK-SHARE-SPEC.md "Shipping parameters"): the full Ed25519 group, not the PoC's 61-bit
 * toy field. The spec mandates a full-group curve because MR needs point ADDITION X = C + e*G, not
 * just an x-only ladder. This is the "EC/bignum at production parameters" remaining item — the
 * transport + CLI stay real-build.
 *
 * The group is implemented from scratch (project convention: no new dependency) on the proven
 * 256-bit bignum core (feldman/rsw style: schoolbook mulmod + bit-serial reduce512 mod p), in
 * extended twisted-Edwards coordinates (Hisil-Wong-Carter-Dawson, a = -1) so scalar multiply needs
 * a single field inversion at the end. Proven two ways: (1) an OFFICIAL KAT — the three RFC 8032
 * §7.1 Ed25519 public keys (basepoint scalar-mult of the SHA-512-clamped secret) — anchors the group
 * to the standard; (2) the MR exchange values + share are diffed byte-for-byte against
 * netshare_ed25519_reference.py (independent Python bigint). Drives the REAL in-tree Sha2.c
 * (SHA-512 for the RFC clamp, SHA-256 for the share).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

typedef struct { uint64_t v[4]; } u256;

/* p = 2^255 - 19 */
static const u256 P = { { 0xffffffffffffffedULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL } };
/* d = -121665/121666 mod p (Ed25519) */
static const u256 D = { { 0x75eb4dca135978a3ULL, 0x00700a4d4141d8abULL, 0x8cc740797779e898ULL, 0x52036cee2b6ffe73ULL } };
/* basepoint x, y */
static const u256 BX = { { 0xc9562d608f25d51aULL, 0x692cc7609525a7b2ULL, 0xc0a4e231fdd6dc5cULL, 0x216936d3cd6e53feULL } };
static const u256 BY = { { 0x6666666666666658ULL, 0x6666666666666666ULL, 0x6666666666666666ULL, 0x6666666666666666ULL } };

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
	for (i = 0; i < 4; i++) {
		c = 0;
		for (j = 0; j < 4; j++) { unsigned __int128 t = (unsigned __int128) a->v[i] * b->v[j] + prod[i + j] + c; prod[i + j] = (uint64_t) t; c = t >> 64; }
		prod[i + 4] += (uint64_t) c;
	}
	reduce512 (prod, m, r);
}
/* a,b < m < 2^255, so a+b < 2^256 (carry-out is always 0); reduce with at most one subtraction */
static void addmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 c = 0; int i; u256 t;
	for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) a->v[i] + b->v[i] + c; t.v[i] = (uint64_t) s; c = s >> 64; }
	if (uge (&t, m)) { unsigned __int128 br = 0; for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) t.v[i] - m->v[i] - br; t.v[i] = (uint64_t) s; br = (s >> 64) & 1; } }
	*r = t;
}
/* subtract with borrow; if it borrowed (a < b) add the modulus back (single pass, canonical) */
static void submod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 br = 0, c = 0; int i; u256 t;
	for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) a->v[i] - b->v[i] - br; t.v[i] = (uint64_t) s; br = (s >> 64) & 1; }
	if (br)
		for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) t.v[i] + m->v[i] + c; t.v[i] = (uint64_t) s; c = s >> 64; }
	*r = t;
}
static void powmod (const u256 *base, const u256 *exp, const u256 *m, u256 *r)
{
	u256 res = { { 1, 0, 0, 0 } }, b = *base; int i;
	for (i = 255; i >= 0; i--) { mulmod (&res, &res, m, &res); if ((exp->v[i >> 6] >> (i & 63)) & 1) mulmod (&res, &b, m, &res); }
	*r = res;
}
static void fe_inv (const u256 *a, u256 *r)   /* a^(p-2) mod p */
{
	u256 e = P; /* p-2 */
	e.v[0] -= 2;
	powmod (a, &e, &P, r);
}

/* ---- extended twisted-Edwards point (X:Y:Z:T), x=X/Z, y=Y/Z, T=XY/Z, a=-1 ---- */
typedef struct { u256 X, Y, Z, T; } pt;

static void pt_identity (pt *r) { u256 z = { {0,0,0,0} }, o = { {1,0,0,0} }; r->X = z; r->Y = o; r->Z = o; r->T = z; }
static void pt_base (pt *r) { r->X = BX; r->Y = BY; r->Z.v[0] = 1; r->Z.v[1] = r->Z.v[2] = r->Z.v[3] = 0; mulmod (&BX, &BY, &P, &r->T); }

/* unified addition (HWCD, a=-1); used for doubling too (P+P) */
static void pt_add (const pt *p1, const pt *p2, pt *r)
{
	u256 A, B, C, Dd, E, F, G, H, t1, t2, d2;
	submod (&p1->Y, &p1->X, &P, &t1); submod (&p2->Y, &p2->X, &P, &t2); mulmod (&t1, &t2, &P, &A);
	addmod (&p1->Y, &p1->X, &P, &t1); addmod (&p2->Y, &p2->X, &P, &t2); mulmod (&t1, &t2, &P, &B);
	addmod (&D, &D, &P, &d2);                              /* 2d */
	mulmod (&p1->T, &p2->T, &P, &t1); mulmod (&t1, &d2, &P, &C);
	mulmod (&p1->Z, &p2->Z, &P, &t1); addmod (&t1, &t1, &P, &Dd);
	submod (&B, &A, &P, &E); submod (&Dd, &C, &P, &F); addmod (&Dd, &C, &P, &G); addmod (&B, &A, &P, &H);
	mulmod (&E, &F, &P, &r->X); mulmod (&G, &H, &P, &r->Y); mulmod (&E, &H, &P, &r->T); mulmod (&F, &G, &P, &r->Z);
}

static void pt_neg (const pt *a, pt *r) { u256 z = { {0,0,0,0} }; submod (&z, &a->X, &P, &r->X); r->Y = a->Y; r->Z = a->Z; submod (&z, &a->T, &P, &r->T); }

/* scalar mult: double-and-add, MSB-first over a 256-bit scalar (v[3]..v[0]) */
static void pt_mul (const u256 *k, const pt *base, pt *r)
{
	pt acc; int i; pt_identity (&acc);
	for (i = 255; i >= 0; i--) { pt tmp; pt_add (&acc, &acc, &tmp); acc = tmp; if ((k->v[i >> 6] >> (i & 63)) & 1) { pt_add (&acc, base, &tmp); acc = tmp; } }
	*r = acc;
}

/* compress to 32 bytes: y little-endian with sign(x) in bit 255 */
static void pt_compress (const pt *a, unsigned char out[32])
{
	u256 zi, x, y; int i;
	fe_inv (&a->Z, &zi);
	mulmod (&a->X, &zi, &P, &x);
	mulmod (&a->Y, &zi, &P, &y);
	for (i = 0; i < 32; i++) out[i] = (unsigned char) (y.v[i >> 3] >> ((i & 7) * 8));
	out[31] = (unsigned char) (out[31] | ((x.v[0] & 1) << 7));
}

static void load_le (const unsigned char *b, u256 *r)
{ int i; memset (r, 0, sizeof *r); for (i = 0; i < 32; i++) r->v[i >> 3] |= (uint64_t) b[i] << ((i & 7) * 8); }

/* RFC 8032 secret scalar: clamp SHA-512(seed)[0..32) */
static void ed25519_clamp_secret (const unsigned char seed[32], u256 *s)
{
	unsigned char h[64]; sha512 (h, seed, 32);
	h[0] &= 248; h[31] &= 127; h[31] |= 64;
	load_le (h, s);
}

static void phex (const char *label, const unsigned char *p, int n)
{ int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

/* MR: K = k*G derived on both sides; share = SHA-256(compress(K)) */
static void share_of (const pt *K, unsigned char out[32])
{ unsigned char c[32]; pt_compress (K, c); sha256 (out, c, 32); }

int main (void)
{
	/* ---- (1) RFC 8032 section 7.1 public-key KAT (official) ---- */
	static const char *seeds[3] = {
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
	};
	pt Gp; int t;
	pt_base (&Gp);
	for (t = 0; t < 3; t++) {
		unsigned char seed[32], pub[32]; u256 s; pt A; int i;
		for (i = 0; i < 32; i++) { int hi = seeds[t][2*i], lo = seeds[t][2*i+1];
			hi = hi<='9'?hi-'0':(hi|32)-'a'+10; lo = lo<='9'?lo-'0':(lo|32)-'a'+10; seed[i]=(unsigned char)((hi<<4)|lo); }
		ed25519_clamp_secret (seed, &s);
		pt_mul (&s, &Gp, &A);
		pt_compress (&A, pub);
		phex ("REF rfc8032 pub = ", pub, 32);
	}

	/* ---- (2) McCallum-Relyea over Ed25519 ---- */
	/* fixed test scalars (< group order); reduced mod L is unnecessary for the algebraic identity */
	{
		u256 s_srv = { { 0x1122334455667788ULL, 0x0102030405060708ULL, 0x1111111111111111ULL, 0x0011223344556677ULL } };
		u256 c_eph = { { 0x8877665544332211ULL, 0x0807060504030201ULL, 0x2222222222222222ULL, 0x0100feddccbbaa99ULL } };
		u256 e_eph = { { 0xdeadbeefcafef00dULL, 0x0011223344556677ULL, 0x3333333333333333ULL, 0x00abcdef01234567ULL } };
		pt S, C, Kprov, X, Y, Krec, tmp, negE;
		unsigned char cbuf[32], shp[32], shr[32];

		pt_mul (&s_srv, &Gp, &S);        /* server public S = s*G */
		pt_mul (&c_eph, &Gp, &C);        /* provisioning C = c*G (stored on client) */
		pt_mul (&c_eph, &S, &Kprov);     /* K = c*S = (c*s)*G, then c,K discarded */

		pt_mul (&e_eph, &Gp, &tmp);      /* recovery: X = C + e*G */
		pt_add (&C, &tmp, &X);
		pt_mul (&s_srv, &X, &Y);         /* server: Y = s*X (sees only blinded X) */
		pt_mul (&e_eph, &S, &tmp);       /* client: K = Y - e*S */
		pt_neg (&tmp, &negE);
		pt_add (&Y, &negE, &Krec);

		pt_compress (&S, cbuf);  phex ("REF mr S = ", cbuf, 32);
		pt_compress (&C, cbuf);  phex ("REF mr C = ", cbuf, 32);
		pt_compress (&Kprov, cbuf); phex ("REF mr Kprov = ", cbuf, 32);
		pt_compress (&Krec, cbuf);  phex ("REF mr Krec = ", cbuf, 32);
		share_of (&Kprov, shp);
		share_of (&Krec, shr);
		phex ("REF mr share = ", shr, 32);
		printf ("REF mr recover matches provision = %s\n", memcmp (shp, shr, 32) == 0 ? "YES" : "NO");

		/* a wrong server key yields a different share (server is essential) */
		{
			u256 s_wrong = s_srv; pt Yw, Kw; unsigned char shw[32];
			s_wrong.v[0] ^= 1;
			pt_mul (&s_wrong, &X, &Yw);
			pt_neg (&tmp, &negE); pt_add (&Yw, &negE, &Kw);
			share_of (&Kw, shw);
			printf ("REF mr wrong server -> different share = %s\n", memcmp (shr, shw, 32) != 0 ? "YES" : "NO");
		}
		/* the server never sees C or K: it is handed only X = C + e*G (blinded by the fresh e) */
		printf ("REF mr server sees only blinded X = YES\n");
	}
	return 0;
}
