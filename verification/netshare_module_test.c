/*
 * netshare_module_test.c — module test for the SHIPPABLE src/Common/NetShare.{c,h}.
 *
 * WHAT THIS ANCHORS, AND WHY IT IS NOT JUST ANOTHER MR POC
 * The McCallum-Relyea exchange itself is already proven four times over: small prime field [10], full
 * Ed25519 [39], AF_UNIX transport [49], real two-host TCP [101]. Every one of those POCs, however, put
 * the RAW extended-coordinate struct on the wire and said so in its header comment ("a production
 * build would send compressed 32-byte points ... a serialization detail"). Nothing in this tree ever
 * had to turn a compressed 32-byte y back into a point. So the shippable module needed genuinely NEW
 * crypto -- RFC 8032 section 5.1.3 decompression, which needs a modular square root -- and new crypto
 * needs its own anchor.
 *
 * ANCHOR CLASS: OFFICIAL. The five Ed25519 public keys in RFC 8032 section 7.1 are compressed points
 * produced by an implementation that is not ours. Decompressing them exercises the square root, the
 * sqrt(-1) branch, the sign-bit reconstruction and the canonicality check against bytes we did not
 * author. Re-compressing must return the identical 32 bytes -- and that is a real test rather than a
 * tautology, because compression recomputes x from the decompressed coordinates: an x recovered on the
 * wrong branch re-encodes with the wrong sign bit and the round-trip fails.
 *
 * Also asserted here (PROPERTY class, fork-specific): the MR protocol over the compressed wire format
 * end to end, the blinding property, off-network failure being distinguishable from a wrong answer,
 * and the negative controls for malformed encodings.
 *
 * Build: see verification/build_and_verify.sh step [102].
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Common/NetShare.h"

static int pass = 0, fail = 0;

static void check (const char *what, int ok)
{
	if (ok) { printf ("    ok   %s\n", what); pass++; }
	else    { printf ("    FAIL %s\n", what); fail++; }
}

static int unhex (const char *h, unsigned char *out, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		unsigned v;
		if (sscanf (h + 2 * i, "%2x", &v) != 1) return -1;
		out[i] = (unsigned char) v;
	}
	return 0;
}

static void phex (const char *label, const unsigned char *p, int n)
{
	int i;
	printf ("%s", label);
	for (i = 0; i < n; i++) printf ("%02x", p[i]);
	printf ("\n");
}

/* --- deterministic RNG so the harness is reproducible (the product passes its real CSPRNG) ------- */
typedef struct { unsigned char seed; } detrng;
static void det_rand (void *ctx, unsigned char *buf, size_t len)
{
	detrng *r = (detrng *) ctx;
	size_t i;
	for (i = 0; i < len; i++) buf[i] = (unsigned char) (r->seed * 7 + i * 31 + 11);
	r->seed++;
}

/* --- in-process transport: hands X to the real server routine and returns Y --------------------- */
typedef struct { const unsigned char *sSeed; int calls; unsigned char lastX[32]; int dead; } srvctx;

static int srv_transport (void *ctx, const unsigned char *req, size_t reqLen,
                          unsigned char *resp, size_t respCap, size_t *respLen)
{
	srvctx *s = (srvctx *) ctx;
	if (s->dead) return -1;                       /* nothing listening: off-network */
	if (reqLen != 32 || respCap < 32) return -1;
	memcpy (s->lastX, req, 32);
	s->calls++;
	if (NetShareServerRespond (s->sSeed, req, resp) != NETSHARE_OK) return -1;
	*respLen = 32;
	return 0;
}

/* A transport that reports success but returns a short reply — must NOT be read as a bad key. */
static int short_transport (void *ctx, const unsigned char *req, size_t reqLen,
                            unsigned char *resp, size_t respCap, size_t *respLen)
{
	(void) ctx; (void) req; (void) reqLen; (void) respCap;
	memset (resp, 0, 32);
	*respLen = 7;
	return 0;
}

int main (void)
{
	/* RFC 8032 section 7.1 public keys — compressed Ed25519 points from the standard. */
	static const char *RFC8032_PUBKEYS[] = {
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", /* TEST 1   */
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", /* TEST 2   */
		"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", /* TEST 3   */
		"278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e", /* TEST 1024 */
		"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"  /* TEST SHA(abc) */
	};
	const int NPK = (int) (sizeof RFC8032_PUBKEYS / sizeof RFC8032_PUBKEYS[0]);
	int i;

	printf ("  NetShare module test (src/Common/NetShare.c)\n");

	/* ---- 1. OFFICIAL anchor: decompress/re-compress the RFC 8032 public keys ------------------- */
	printf ("  [1] RFC 8032 s7.1 compressed points: decompress -> re-compress is byte-identical\n");
	for (i = 0; i < NPK; i++)
	{
		unsigned char enc[32], rt[32];
		char label[64];
		if (unhex (RFC8032_PUBKEYS[i], enc, 32) != 0) { printf ("    bad vector\n"); return 1; }
		sprintf (label, "RFC 8032 pubkey #%d decompresses and round-trips", i + 1);
		check (label, NetSharePointRoundTrip (enc, rt) == NETSHARE_OK && memcmp (enc, rt, 32) == 0);
	}

	/* ---- 2. negative controls on the encoding -------------------------------------------------- */
	printf ("  [2] malformed encodings are rejected (not silently accepted)\n");
	{
		unsigned char bad[32];
		/* y = p is non-canonical (p = 2^255-19 -> 0xed,0xff...0x7f) */
		memset (bad, 0xff, 32); bad[0] = 0xed; bad[31] = 0x7f;
		check ("non-canonical y == p rejected", NetSharePointValidate (bad) == NETSHARE_ERR_POINT);

		/* y = p+1 likewise */
		memset (bad, 0xff, 32); bad[0] = 0xee; bad[31] = 0x7f;
		check ("non-canonical y == p+1 rejected", NetSharePointValidate (bad) == NETSHARE_ERR_POINT);

		/* A y with no square root: search a few until one is off-curve. */
		{
			int found = 0;
			unsigned char t[32];
			for (i = 2; i < 40 && !found; i++)
			{
				memset (t, 0, 32); t[0] = (unsigned char) i;
				if (NetSharePointValidate (t) == NETSHARE_ERR_POINT) found = 1;
			}
			check ("an off-curve y is rejected", found);
		}

		/* x == 0 with the sign bit set is the RFC-invalid encoding: y = 1 gives x = 0. */
		memset (bad, 0, 32); bad[0] = 1; bad[31] = 0x80;
		check ("x==0 with sign bit set rejected", NetSharePointValidate (bad) == NETSHARE_ERR_POINT);

		/* ... while y = 1 with the sign bit clear is the valid identity encoding. */
		memset (bad, 0, 32); bad[0] = 1;
		check ("identity (y==1, sign 0) accepted", NetSharePointValidate (bad) == NETSHARE_OK);
	}

	/* ---- 3. MR end to end over the compressed wire format --------------------------------------- */
	printf ("  [3] McCallum-Relyea over the compressed wire format\n");
	{
		unsigned char sSeed[32], sSeed2[32], S[32], S2[32];
		unsigned char cred[NETSHARE_CRED_LEN], enrolShare[32], rec1[32], rec2[32];
		detrng rng; srvctx srv, srvWrong;
		unsigned char X1[32], X2[32], Cstored[32], Sparsed[32];

		for (i = 0; i < 32; i++) { sSeed[i] = (unsigned char) (0x11 * i + 3); sSeed2[i] = (unsigned char) (0x55 * i + 2); }
		check ("server public S = s*G", NetShareServerPublic (sSeed, S) == NETSHARE_OK);
		check ("wrong-server public S2", NetShareServerPublic (sSeed2, S2) == NETSHARE_OK);

		rng.seed = 1;
		check ("enrol produces a credential + share",
		       NetShareEnroll (S, det_rand, &rng, cred, enrolShare) == NETSHARE_OK);
		phex ("    enrolled share : ", enrolShare, 32);

		check ("credential parses", NetShareCredParse (cred, sizeof cred, Sparsed, Cstored) == NETSHARE_OK);
		check ("credential carries the server's S", memcmp (Sparsed, S, 32) == 0);

		srv.sSeed = sSeed; srv.calls = 0; srv.dead = 0;
		rng.seed = 50;
		check ("recover #1 succeeds",
		       NetShareRecover (cred, sizeof cred, srv_transport, &srv, det_rand, &rng, rec1) == NETSHARE_OK);
		memcpy (X1, srv.lastX, 32);
		phex ("    recovered #1   : ", rec1, 32);
		check ("recover #1 == enrolled share", memcmp (rec1, enrolShare, 32) == 0);

		rng.seed = 200;                                   /* a DIFFERENT blinding e */
		check ("recover #2 succeeds",
		       NetShareRecover (cred, sizeof cred, srv_transport, &srv, det_rand, &rng, rec2) == NETSHARE_OK);
		memcpy (X2, srv.lastX, 32);
		check ("recover #2 == enrolled share (blinding does not change K)", memcmp (rec2, enrolShare, 32) == 0);

		/* Server-obliviousness: the server never sees C, and cannot link two recoveries. */
		check ("blinded X != stored C (server never sees C)", memcmp (X1, Cstored, 32) != 0);
		check ("X differs between recoveries (unlinkable)", memcmp (X1, X2, 32) != 0);

		/* Off-network must be a TRANSPORT error, never a wrong-key answer. */
		srv.dead = 1;
		rng.seed = 7;
		check ("off-network returns ERR_TRANSPORT, not a bad share",
		       NetShareRecover (cred, sizeof cred, srv_transport, &srv, det_rand, &rng, rec1)
		           == NETSHARE_ERR_TRANSPORT);
		srv.dead = 0;

		check ("short reply returns ERR_TRANSPORT, not a bad share",
		       NetShareRecover (cred, sizeof cred, short_transport, NULL, det_rand, &rng, rec1)
		           == NETSHARE_ERR_TRANSPORT);

		/* Wrong server: reachable, answers, but with a different secret -> a DIFFERENT share. */
		srvWrong.sSeed = sSeed2; srvWrong.calls = 0; srvWrong.dead = 0;
		rng.seed = 9;
		check ("wrong server still returns OK (it is reachable)",
		       NetShareRecover (cred, sizeof cred, srv_transport, &srvWrong, det_rand, &rng, rec2) == NETSHARE_OK);
		check ("wrong server yields a DIFFERENT share", memcmp (rec2, enrolShare, 32) != 0);
	}

	/* ---- 4. credential blob negative controls ---------------------------------------------------- */
	printf ("  [4] credential blob validation\n");
	{
		unsigned char cred[NETSHARE_CRED_LEN], S[32], C[32], outS[32], outC[32];
		unsigned char sSeed[32];
		detrng rng; rng.seed = 3;
		for (i = 0; i < 32; i++) sSeed[i] = (unsigned char) (i + 1);
		NetShareServerPublic (sSeed, S);
		{
			unsigned char share[32];
			NetShareEnroll (S, det_rand, &rng, cred, share);
		}
		check ("valid credential parses", NetShareCredParse (cred, sizeof cred, outS, outC) == NETSHARE_OK);

		check ("short blob rejected", NetShareCredParse (cred, sizeof cred - 1, outS, outC) == NETSHARE_ERR_CRED);

		memcpy (C, cred, 4);
		cred[0] = 'X';
		check ("bad magic rejected", NetShareCredParse (cred, sizeof cred, outS, outC) == NETSHARE_ERR_CRED);
		cred[0] = 'N';

		cred[3] = 99;
		check ("unknown version rejected", NetShareCredParse (cred, sizeof cred, outS, outC) == NETSHARE_ERR_CRED);
		cred[3] = NETSHARE_CRED_VERSION;

		/*
		 * A corrupt point inside a well-formed blob must be a CREDENTIAL error, never a failed unlock.
		 * This is the check that found the real gap: Ed25519 point encodings are dense, so flipping a
		 * bit in S usually lands on ANOTHER VALID POINT. Point validation alone therefore returned OK
		 * and recovery would have silently produced a different share, surfacing to the user as "wrong
		 * password". The credential now carries a checksum so corruption is named as corruption.
		 * Sweep several bit positions rather than one, so this cannot pass by luck.
		 */
		{
			int b, allCred = 1, anyStillValidPoint = 0;
			for (b = 0; b < 8; b++)
			{
				unsigned char tmp[NETSHARE_CRED_LEN];
				memcpy (tmp, cred, sizeof tmp);
				tmp[4 + b * 3] ^= (unsigned char) (1u << (b & 7));
				if (NetShareCredParse (tmp, sizeof tmp, outS, outC) != NETSHARE_ERR_CRED) allCred = 0;
				/* record whether the mutated point would still have passed validation alone */
				if (NetSharePointValidate (tmp + 4) == NETSHARE_OK) anyStillValidPoint = 1;
			}
			check ("corrupt point -> ERR_CRED for every probed bit flip", allCred);
			check ("(and at least one flip yields a still-valid point, so the checksum is load-bearing)",
			       anyStillValidPoint);
		}
	}

	printf ("  NETSHARE MODULE: %d passed, %d failed\n", pass, fail);
	if (fail) { printf ("  NETSHARE MODULE TEST FAILED\n"); return 1; }
	printf ("  NETSHARE MODULE TEST PASSED\n");
	return 0;
}
