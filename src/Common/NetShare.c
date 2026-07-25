/*
 * NetShare.c — McCallum–Relyea network-bound share over Ed25519, with a real compressed wire format.
 *
 * The group arithmetic is the same extended twisted-Edwards implementation proven in
 * verification/netshare_ed25519_poc.c (step [39], anchored to the RFC 8032 section 7.1 public keys)
 * and driven over a real transport in steps [49] / [101]. What is NEW here, and what this module
 * exists for, is NetSharePointDecompress: the POCs put raw coordinates on the wire, so nothing in
 * this tree ever had to recover x from a compressed y. See NetShare.h for why that mattered.
 *
 * Style follows the surrounding Common/ C: no dynamic allocation, no platform headers, secrets wiped
 * on every exit path.
 */

#include "Common/NetShare.h"

#if defined(VC_ENABLE_NETSHARE)

#include <string.h>
#include <stdint.h>
#include "Crypto/Sha2.h"

/* ---- 256-bit field arithmetic mod p = 2^255 - 19 ------------------------------------------------ */

typedef struct { uint64_t v[4]; } u256;

static const u256 FP = { { 0xffffffffffffffedULL, 0xffffffffffffffffULL,
                           0xffffffffffffffffULL, 0x7fffffffffffffffULL } };
static const u256 FD = { { 0x75eb4dca135978a3ULL, 0x00700a4d4141d8abULL,
                           0x8cc740797779e898ULL, 0x52036cee2b6ffe73ULL } };
static const u256 BX = { { 0xc9562d608f25d51aULL, 0x692cc7609525a7b2ULL,
                           0xc0a4e231fdd6dc5cULL, 0x216936d3cd6e53feULL } };
static const u256 BY = { { 0x6666666666666658ULL, 0x6666666666666666ULL,
                           0x6666666666666666ULL, 0x6666666666666666ULL } };

static int ucmp (const u256 *a, const u256 *b)
{
	int i;
	for (i = 3; i >= 0; i--) { if (a->v[i] < b->v[i]) return -1; if (a->v[i] > b->v[i]) return 1; }
	return 0;
}
static int uge (const u256 *a, const u256 *b) { return ucmp (a, b) >= 0; }
static int uiszero (const u256 *a) { return (a->v[0] | a->v[1] | a->v[2] | a->v[3]) == 0; }

static void reduce512 (const uint64_t prod[8], const u256 *m, u256 *r)
{
	uint64_t rem[5]; int bit, k;
	memset (rem, 0, sizeof rem);
	for (bit = 511; bit >= 0; bit--)
	{
		uint64_t carry = (prod[bit >> 6] >> (bit & 63)) & 1, nc;
		for (k = 0; k < 5; k++) { nc = rem[k] >> 63; rem[k] = (rem[k] << 1) | carry; carry = nc; }
		for (;;)
		{
			u256 lo; int i; unsigned __int128 br = 0;
			lo.v[0] = rem[0]; lo.v[1] = rem[1]; lo.v[2] = rem[2]; lo.v[3] = rem[3];
			if (rem[4] == 0 && !uge (&lo, m)) break;
			for (i = 0; i < 4; i++)
			{
				unsigned __int128 t = (unsigned __int128) rem[i] - m->v[i] - br;
				rem[i] = (uint64_t) t; br = (t >> 64) & 1;
			}
			rem[4] -= (uint64_t) br;
		}
	}
	r->v[0] = rem[0]; r->v[1] = rem[1]; r->v[2] = rem[2]; r->v[3] = rem[3];
}

static void mulmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	uint64_t prod[8]; unsigned __int128 c; int i, j;
	memset (prod, 0, sizeof prod);
	for (i = 0; i < 4; i++)
	{
		c = 0;
		for (j = 0; j < 4; j++)
		{
			unsigned __int128 t = (unsigned __int128) a->v[i] * b->v[j] + prod[i + j] + c;
			prod[i + j] = (uint64_t) t; c = t >> 64;
		}
		prod[i + 4] += (uint64_t) c;
	}
	reduce512 (prod, m, r);
}

static void addmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 c = 0; int i; u256 t;
	for (i = 0; i < 4; i++)
	{
		unsigned __int128 s = (unsigned __int128) a->v[i] + b->v[i] + c;
		t.v[i] = (uint64_t) s; c = s >> 64;
	}
	if (uge (&t, m))
	{
		unsigned __int128 br = 0;
		for (i = 0; i < 4; i++)
		{
			unsigned __int128 s = (unsigned __int128) t.v[i] - m->v[i] - br;
			t.v[i] = (uint64_t) s; br = (s >> 64) & 1;
		}
	}
	*r = t;
}

static void submod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 br = 0, c = 0; int i; u256 t;
	for (i = 0; i < 4; i++)
	{
		unsigned __int128 s = (unsigned __int128) a->v[i] - b->v[i] - br;
		t.v[i] = (uint64_t) s; br = (s >> 64) & 1;
	}
	if (br)
		for (i = 0; i < 4; i++)
		{
			unsigned __int128 s = (unsigned __int128) t.v[i] + m->v[i] + c;
			t.v[i] = (uint64_t) s; c = s >> 64;
		}
	*r = t;
}

static void powmod (const u256 *base, const u256 *exp, const u256 *m, u256 *r)
{
	u256 res, b = *base; int i;
	res.v[0] = 1; res.v[1] = res.v[2] = res.v[3] = 0;
	for (i = 255; i >= 0; i--)
	{
		mulmod (&res, &res, m, &res);
		if ((exp->v[i >> 6] >> (i & 63)) & 1) mulmod (&res, &b, m, &res);
	}
	*r = res;
}

static void fe_inv (const u256 *a, u256 *r) { u256 e = FP; e.v[0] -= 2; powmod (a, &e, &FP, r); }

/* ---- group ------------------------------------------------------------------------------------- */

typedef struct { u256 X, Y, Z, T; } pt;

static void pt_identity (pt *r)
{
	memset (r, 0, sizeof *r);
	r->Y.v[0] = 1; r->Z.v[0] = 1;
}
static void pt_base (pt *r)
{
	r->X = BX; r->Y = BY;
	r->Z.v[0] = 1; r->Z.v[1] = r->Z.v[2] = r->Z.v[3] = 0;
	mulmod (&BX, &BY, &FP, &r->T);
}
static void pt_add (const pt *p1, const pt *p2, pt *r)
{
	u256 A, B, C, Dd, E, F, G, H, t1, t2, d2;
	submod (&p1->Y, &p1->X, &FP, &t1); submod (&p2->Y, &p2->X, &FP, &t2); mulmod (&t1, &t2, &FP, &A);
	addmod (&p1->Y, &p1->X, &FP, &t1); addmod (&p2->Y, &p2->X, &FP, &t2); mulmod (&t1, &t2, &FP, &B);
	addmod (&FD, &FD, &FP, &d2);
	mulmod (&p1->T, &p2->T, &FP, &t1); mulmod (&t1, &d2, &FP, &C);
	mulmod (&p1->Z, &p2->Z, &FP, &t1); addmod (&t1, &t1, &FP, &Dd);
	submod (&B, &A, &FP, &E); submod (&Dd, &C, &FP, &F);
	addmod (&Dd, &C, &FP, &G); addmod (&B, &A, &FP, &H);
	mulmod (&E, &F, &FP, &r->X); mulmod (&G, &H, &FP, &r->Y);
	mulmod (&E, &H, &FP, &r->T); mulmod (&F, &G, &FP, &r->Z);
}
static void pt_neg (const pt *a, pt *r)
{
	u256 z; memset (&z, 0, sizeof z);
	submod (&z, &a->X, &FP, &r->X); r->Y = a->Y; r->Z = a->Z; submod (&z, &a->T, &FP, &r->T);
}
static void pt_mul (const u256 *k, const pt *base, pt *r)
{
	pt acc; int i;
	pt_identity (&acc);
	for (i = 255; i >= 0; i--)
	{
		pt tmp;
		pt_add (&acc, &acc, &tmp); acc = tmp;
		if ((k->v[i >> 6] >> (i & 63)) & 1) { pt_add (&acc, base, &tmp); acc = tmp; }
	}
	*r = acc;
}

static void fe_to_bytes (const u256 *a, unsigned char out[32])
{
	int i;
	for (i = 0; i < 32; i++) out[i] = (unsigned char) (a->v[i >> 3] >> ((i & 7) * 8));
}
static void fe_from_bytes (const unsigned char b[32], u256 *r)
{
	int i;
	memset (r, 0, sizeof *r);
	for (i = 0; i < 32; i++) r->v[i >> 3] |= (uint64_t) b[i] << ((i & 7) * 8);
}

static void pt_compress (const pt *a, unsigned char out[NETSHARE_POINT_LEN])
{
	u256 zi, x, y;
	fe_inv (&a->Z, &zi);
	mulmod (&a->X, &zi, &FP, &x);
	mulmod (&a->Y, &zi, &FP, &y);
	fe_to_bytes (&y, out);
	out[31] = (unsigned char) (out[31] | ((x.v[0] & 1) << 7));
}

/*
 * Point decompression — RFC 8032 section 5.1.3. THE NEW CRYPTO IN THIS MODULE.
 *
 *   y = enc without the sign bit;  reject if y >= p (non-canonical encoding)
 *   u = y^2 - 1,  v = d*y^2 + 1,  and we need x with x^2 = u/v
 *   candidate x = (u/v)^((p+3)/8) = u*v^3 * (u*v^7)^((p-5)/8)
 *   if v*x^2 == u        accept
 *   else if v*x^2 == -u  x *= sqrt(-1)
 *   else                 no square root -> not on the curve
 *   reject x == 0 with sign bit set (the one encoding RFC 8032 calls invalid)
 *   if sign(x) != sign bit, x = p - x
 *
 * sqrt(-1) is computed rather than hardcoded (2^((p-1)/4) mod p): a mistyped 256-bit constant would
 * be a silent wrong-branch bug, and this runs once per decompression on a non-hot path.
 */
static int pt_decompress (const unsigned char enc[NETSHARE_POINT_LEN], pt *out)
{
	unsigned char ybytes[32];
	u256 y, y2, u, v, v3, v7, uv3, uv7, e, x, x2, vx2, negu, sq, chk;
	int signBit, i;

	memcpy (ybytes, enc, 32);
	signBit = (ybytes[31] >> 7) & 1;
	ybytes[31] &= 0x7f;
	fe_from_bytes (ybytes, &y);

	/* Non-canonical y (>= p) is rejected: two encodings of one point would otherwise exist. */
	if (uge (&y, &FP)) return NETSHARE_ERR_POINT;

	mulmod (&y, &y, &FP, &y2);
	{
		u256 one; memset (&one, 0, sizeof one); one.v[0] = 1;
		submod (&y2, &one, &FP, &u);              /* u = y^2 - 1 */
		mulmod (&FD, &y2, &FP, &v);
		addmod (&v, &one, &FP, &v);               /* v = d*y^2 + 1 */
	}

	mulmod (&v, &v, &FP, &v3); mulmod (&v3, &v, &FP, &v3);          /* v^3 */
	mulmod (&v3, &v3, &FP, &v7); mulmod (&v7, &v, &FP, &v7);        /* v^7 */
	mulmod (&u, &v3, &FP, &uv3);
	mulmod (&u, &v7, &FP, &uv7);

	/* e = (p-5)/8 = 2^252 - 3 */
	e = FP; e.v[0] -= 5;
	for (i = 0; i < 3; i++)
	{
		int k; uint64_t carry = 0;
		for (k = 3; k >= 0; k--) { uint64_t nc = e.v[k] & 1; e.v[k] = (e.v[k] >> 1) | (carry << 63); carry = nc; }
	}
	powmod (&uv7, &e, &FP, &x);
	mulmod (&uv3, &x, &FP, &x);

	mulmod (&x, &x, &FP, &x2);
	mulmod (&v, &x2, &FP, &vx2);
	{
		u256 z; memset (&z, 0, sizeof z);
		submod (&z, &u, &FP, &negu);
	}

	if (ucmp (&vx2, &u) != 0)
	{
		if (ucmp (&vx2, &negu) == 0)
		{
			/* sqrt(-1) = 2^((p-1)/4) mod p; (p-1)/4 = 2^253 - 5 */
			u256 q = FP, two; int k; uint64_t carry;
			memset (&two, 0, sizeof two); two.v[0] = 2;
			q.v[0] -= 1;
			for (i = 0; i < 2; i++)
			{
				carry = 0;
				for (k = 3; k >= 0; k--) { uint64_t nc = q.v[k] & 1; q.v[k] = (q.v[k] >> 1) | (carry << 63); carry = nc; }
			}
			powmod (&two, &q, &FP, &sq);
			mulmod (&x, &sq, &FP, &x);
		}
		else
		{
			memset (&x, 0, sizeof x);
			return NETSHARE_ERR_POINT;              /* u/v is not a square: not on the curve */
		}
	}

	/* Re-check after the sqrt(-1) correction — a wrong branch must not slip through. */
	mulmod (&x, &x, &FP, &x2);
	mulmod (&v, &x2, &FP, &chk);
	if (ucmp (&chk, &u) != 0) return NETSHARE_ERR_POINT;

	if (uiszero (&x) && signBit) return NETSHARE_ERR_POINT;   /* RFC 8032: invalid encoding */

	if ((int) (x.v[0] & 1) != signBit)
	{
		u256 z; memset (&z, 0, sizeof z);
		submod (&z, &x, &FP, &x);
	}

	out->X = x; out->Y = y;
	memset (&out->Z, 0, sizeof out->Z); out->Z.v[0] = 1;
	mulmod (&x, &y, &FP, &out->T);
	return NETSHARE_OK;
}

static void clamp_scalar (const unsigned char seed[NETSHARE_SCALAR_LEN], u256 *s)
{
	unsigned char h[32];
	memcpy (h, seed, 32);
	h[0] &= 248; h[31] &= 127; h[31] |= 64;         /* RFC 8032 section 5.1.5 */
	fe_from_bytes (h, s);
	memset (h, 0, sizeof h);
}

static void ns_wipe (void *p, size_t n)
{
	volatile unsigned char *q = (volatile unsigned char *) p;
	while (n--) *q++ = 0;
}

/* ---- public API --------------------------------------------------------------------------------- */

int NetSharePointValidate (const unsigned char enc[NETSHARE_POINT_LEN])
{
	pt p;
	int rc;
	if (!enc) return NETSHARE_ERR_PARAM;
	rc = pt_decompress (enc, &p);
	ns_wipe (&p, sizeof p);
	return rc;
}

int NetSharePointRoundTrip (const unsigned char enc[NETSHARE_POINT_LEN],
                            unsigned char out[NETSHARE_POINT_LEN])
{
	pt p;
	int rc;
	if (!enc || !out) return NETSHARE_ERR_PARAM;
	rc = pt_decompress (enc, &p);
	if (rc == NETSHARE_OK) pt_compress (&p, out);
	ns_wipe (&p, sizeof p);
	return rc;
}

/* cksum = first 4 bytes of SHA-256 over everything preceding it. Detects corruption; see NetShare.h
   for why point validation alone is NOT enough (a flipped bit usually lands on another valid point). */
static void cred_cksum (const unsigned char *blob, unsigned char out[NETSHARE_CRED_CKSUM_LEN])
{
	unsigned char h[32];
	sha256 (h, blob, (unsigned long) (NETSHARE_CRED_LEN - NETSHARE_CRED_CKSUM_LEN));
	memcpy (out, h, NETSHARE_CRED_CKSUM_LEN);
	ns_wipe (h, sizeof h);
}

int NetShareCredSerialise (const unsigned char S[NETSHARE_POINT_LEN],
                           const unsigned char C[NETSHARE_POINT_LEN],
                           unsigned char out[NETSHARE_CRED_LEN])
{
	if (!S || !C || !out) return NETSHARE_ERR_PARAM;
	out[0] = 'N'; out[1] = 'S'; out[2] = 'C'; out[3] = (unsigned char) NETSHARE_CRED_VERSION;
	memcpy (out + 4, S, NETSHARE_POINT_LEN);
	memcpy (out + 4 + NETSHARE_POINT_LEN, C, NETSHARE_POINT_LEN);
	cred_cksum (out, out + 4 + NETSHARE_POINT_LEN * 2);
	return NETSHARE_OK;
}

int NetShareCredParse (const unsigned char *blob, size_t blobLen,
                       unsigned char S[NETSHARE_POINT_LEN],
                       unsigned char C[NETSHARE_POINT_LEN])
{
	unsigned char want[NETSHARE_CRED_CKSUM_LEN];

	if (!blob || !S || !C) return NETSHARE_ERR_PARAM;
	if (blobLen != NETSHARE_CRED_LEN) return NETSHARE_ERR_CRED;
	if (blob[0] != 'N' || blob[1] != 'S' || blob[2] != 'C') return NETSHARE_ERR_CRED;
	if (blob[3] != NETSHARE_CRED_VERSION) return NETSHARE_ERR_CRED;

	cred_cksum (blob, want);
	if (memcmp (want, blob + 4 + NETSHARE_POINT_LEN * 2, NETSHARE_CRED_CKSUM_LEN) != 0)
		return NETSHARE_ERR_CRED;

	/* Validate both points here rather than at first use, so a structurally invalid credential is also
	   reported as a credential problem and never as a failed unlock. */
	if (NetSharePointValidate (blob + 4) != NETSHARE_OK) return NETSHARE_ERR_CRED;
	if (NetSharePointValidate (blob + 4 + NETSHARE_POINT_LEN) != NETSHARE_OK) return NETSHARE_ERR_CRED;
	memcpy (S, blob + 4, NETSHARE_POINT_LEN);
	memcpy (C, blob + 4 + NETSHARE_POINT_LEN, NETSHARE_POINT_LEN);
	return NETSHARE_OK;
}

int NetShareServerPublic (const unsigned char sSeed[NETSHARE_SCALAR_LEN],
                          unsigned char S[NETSHARE_POINT_LEN])
{
	u256 s; pt G, P;
	if (!sSeed || !S) return NETSHARE_ERR_PARAM;
	clamp_scalar (sSeed, &s);
	pt_base (&G);
	pt_mul (&s, &G, &P);
	pt_compress (&P, S);
	ns_wipe (&s, sizeof s); ns_wipe (&P, sizeof P);
	return NETSHARE_OK;
}

int NetShareServerRespond (const unsigned char sSeed[NETSHARE_SCALAR_LEN],
                           const unsigned char X[NETSHARE_POINT_LEN],
                           unsigned char Y[NETSHARE_POINT_LEN])
{
	u256 s; pt Xp, Yp;
	int rc;
	if (!sSeed || !X || !Y) return NETSHARE_ERR_PARAM;
	rc = pt_decompress (X, &Xp);
	if (rc != NETSHARE_OK) return rc;
	clamp_scalar (sSeed, &s);
	pt_mul (&s, &Xp, &Yp);
	pt_compress (&Yp, Y);
	ns_wipe (&s, sizeof s); ns_wipe (&Xp, sizeof Xp); ns_wipe (&Yp, sizeof Yp);
	return NETSHARE_OK;
}

int NetShareEnroll (const unsigned char S[NETSHARE_POINT_LEN],
                    NetShareRandFn rand, void *randCtx,
                    unsigned char credOut[NETSHARE_CRED_LEN],
                    unsigned char shareOut[NETSHARE_SHARE_LEN])
{
	unsigned char cseed[NETSHARE_SCALAR_LEN], Cenc[NETSHARE_POINT_LEN], Kenc[NETSHARE_POINT_LEN];
	u256 c; pt G, Sp, Cp, Kp;
	int rc;

	if (!S || !rand || !credOut || !shareOut) return NETSHARE_ERR_PARAM;

	rc = pt_decompress (S, &Sp);
	if (rc != NETSHARE_OK) return rc;

	rand (randCtx, cseed, sizeof cseed);
	clamp_scalar (cseed, &c);

	pt_base (&G);
	pt_mul (&c, &G, &Cp);          /* C = c*G  (public, stored) */
	pt_mul (&c, &Sp, &Kp);         /* K = c*S  (secret, discarded after hashing) */

	pt_compress (&Cp, Cenc);
	pt_compress (&Kp, Kenc);
	sha256 (shareOut, Kenc, NETSHARE_POINT_LEN);
	rc = NetShareCredSerialise (S, Cenc, credOut);

	/* c and K must not survive enrolment: the whole point is that a stolen disk holds only public
	   values and therefore cannot recover the share without the server. */
	ns_wipe (cseed, sizeof cseed); ns_wipe (&c, sizeof c);
	ns_wipe (&Kp, sizeof Kp); ns_wipe (Kenc, sizeof Kenc);
	ns_wipe (&Cp, sizeof Cp); ns_wipe (&Sp, sizeof Sp);
	return rc;
}

int NetShareRecover (const unsigned char *cred, size_t credLen,
                     NetShareTransportFn transport, void *transportCtx,
                     NetShareRandFn rand, void *randCtx,
                     unsigned char shareOut[NETSHARE_SHARE_LEN])
{
	unsigned char Senc[NETSHARE_POINT_LEN], Cenc[NETSHARE_POINT_LEN];
	unsigned char eseed[NETSHARE_SCALAR_LEN];
	unsigned char Xenc[NETSHARE_POINT_LEN], Yenc[NETSHARE_POINT_LEN], Kenc[NETSHARE_POINT_LEN];
	u256 e; pt G, Sp, Cp, eG, Xp, Yp, eS, negeS, Kp;
	size_t respLen = 0;
	int rc;

	if (!cred || !transport || !rand || !shareOut) return NETSHARE_ERR_PARAM;

	rc = NetShareCredParse (cred, credLen, Senc, Cenc);
	if (rc != NETSHARE_OK) return rc;
	if (pt_decompress (Senc, &Sp) != NETSHARE_OK) return NETSHARE_ERR_CRED;
	if (pt_decompress (Cenc, &Cp) != NETSHARE_OK) return NETSHARE_ERR_CRED;

	/* Fresh blinding every call: two recoveries of one credential put different X on the wire, so the
	   server cannot correlate them or learn C. */
	rand (randCtx, eseed, sizeof eseed);
	clamp_scalar (eseed, &e);

	pt_base (&G);
	pt_mul (&e, &G, &eG);
	pt_add (&Cp, &eG, &Xp);        /* X = C + e*G */
	pt_compress (&Xp, Xenc);

	rc = transport (transportCtx, Xenc, NETSHARE_POINT_LEN, Yenc, sizeof Yenc, &respLen);
	if (rc != 0 || respLen != NETSHARE_POINT_LEN)
	{
		/* Off-network / refused / short reply. Reported as a TRANSPORT error and never as a bad key,
		   so the caller can say "server unreachable" rather than "wrong password". */
		ns_wipe (eseed, sizeof eseed); ns_wipe (&e, sizeof e);
		ns_wipe (&eG, sizeof eG); ns_wipe (&Xp, sizeof Xp);
		return NETSHARE_ERR_TRANSPORT;
	}

	if (pt_decompress (Yenc, &Yp) != NETSHARE_OK)
	{
		ns_wipe (eseed, sizeof eseed); ns_wipe (&e, sizeof e);
		return NETSHARE_ERR_POINT;
	}

	pt_mul (&e, &Sp, &eS);
	pt_neg (&eS, &negeS);
	pt_add (&Yp, &negeS, &Kp);     /* K = Y - e*S = c*S */

	pt_compress (&Kp, Kenc);
	sha256 (shareOut, Kenc, NETSHARE_POINT_LEN);

	ns_wipe (eseed, sizeof eseed); ns_wipe (&e, sizeof e);
	ns_wipe (&eG, sizeof eG); ns_wipe (&eS, sizeof eS); ns_wipe (&negeS, sizeof negeS);
	ns_wipe (&Kp, sizeof Kp); ns_wipe (Kenc, sizeof Kenc);
	ns_wipe (&Xp, sizeof Xp); ns_wipe (&Yp, sizeof Yp);
	return NETSHARE_OK;
}

#endif /* VC_ENABLE_NETSHARE */
