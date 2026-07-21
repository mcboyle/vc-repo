/*
 * netshare_transport_poc.c — the network-bound share END TO END over a real transport
 * (docs/NETWORK-SHARE-SPEC.md "What remains to build"): the McCallum-Relyea exchange, proven at
 * production parameters in netshare_ed25519_poc.c, driven through an actual socket to a separate
 * server process, with a stored recovery blob. This closes the "client transport + C-blob format +
 * enroll/unlock" item as far as a sandbox can: the server runs in a forked child reached over a
 * kernel AF_UNIX socketpair (a genuine transport, not an in-process call), and the off-network case
 * is exercised by refusing to talk to it.
 *
 * Protocol (MR, same math as netshare_ed25519_poc.c, so this reuses the from-scratch Ed25519 group):
 *   server secret s, public S = s*G  (published; the client learns S at enroll)
 *   ENROLL (client, no server round-trip needed): pick c; C = c*G; the share is K = c*S, i.e.
 *          share = SHA-256(compress(c*S)). Persist the blob { S, C }.  <- the "C-blob"
 *   UNLOCK (client -> server -> client): pick a FRESH ephemeral e; send X = C + e*G to the server;
 *          the server returns Y = s*X; the client computes K = Y - e*S = s*C = c*S, recovering the
 *          same share. The server sees only the blinded X (never C, never K, never the share).
 *
 * Asserts, all against the REAL in-tree Sha2.c: (1) the share recovered over the socket equals the
 * enrolled share; (2) each unlock blinds with a fresh e, so X != C and X changes every time (the
 * server cannot correlate); (3) OFF-NETWORK (no server) recovery is impossible; (4) a different
 * server key yields a different share (the server is essential). A production build would send
 * compressed points (32 B) and speak HTTP(S) to a Tang server; here points cross the socket in the
 * extended-coordinate wire form and the blob stores C the same way (decompression is a serialization
 * detail, not part of the protocol) — called out honestly, validation not shipping code.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include "Crypto/Sha2.h"

typedef struct { uint64_t v[4]; } u256;

static const u256 P  = { { 0xffffffffffffffedULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL } };
static const u256 D  = { { 0x75eb4dca135978a3ULL, 0x00700a4d4141d8abULL, 0x8cc740797779e898ULL, 0x52036cee2b6ffe73ULL } };
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
static void addmod (const u256 *a, const u256 *b, const u256 *m, u256 *r)
{
	unsigned __int128 c = 0; int i; u256 t;
	for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) a->v[i] + b->v[i] + c; t.v[i] = (uint64_t) s; c = s >> 64; }
	if (uge (&t, m)) { unsigned __int128 br = 0; for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) t.v[i] - m->v[i] - br; t.v[i] = (uint64_t) s; br = (s >> 64) & 1; } }
	*r = t;
}
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
static void fe_inv (const u256 *a, u256 *r) { u256 e = P; e.v[0] -= 2; powmod (a, &e, &P, r); }

typedef struct { u256 X, Y, Z, T; } pt;
static void pt_identity (pt *r) { u256 z = { {0,0,0,0} }, o = { {1,0,0,0} }; r->X = z; r->Y = o; r->Z = o; r->T = z; }
static void pt_base (pt *r) { r->X = BX; r->Y = BY; r->Z.v[0] = 1; r->Z.v[1] = r->Z.v[2] = r->Z.v[3] = 0; mulmod (&BX, &BY, &P, &r->T); }
static void pt_add (const pt *p1, const pt *p2, pt *r)
{
	u256 A, B, C, Dd, E, F, G, H, t1, t2, d2;
	submod (&p1->Y, &p1->X, &P, &t1); submod (&p2->Y, &p2->X, &P, &t2); mulmod (&t1, &t2, &P, &A);
	addmod (&p1->Y, &p1->X, &P, &t1); addmod (&p2->Y, &p2->X, &P, &t2); mulmod (&t1, &t2, &P, &B);
	addmod (&D, &D, &P, &d2);
	mulmod (&p1->T, &p2->T, &P, &t1); mulmod (&t1, &d2, &P, &C);
	mulmod (&p1->Z, &p2->Z, &P, &t1); addmod (&t1, &t1, &P, &Dd);
	submod (&B, &A, &P, &E); submod (&Dd, &C, &P, &F); addmod (&Dd, &C, &P, &G); addmod (&B, &A, &P, &H);
	mulmod (&E, &F, &P, &r->X); mulmod (&G, &H, &P, &r->Y); mulmod (&E, &H, &P, &r->T); mulmod (&F, &G, &P, &r->Z);
}
static void pt_neg (const pt *a, pt *r) { u256 z = { {0,0,0,0} }; submod (&z, &a->X, &P, &r->X); r->Y = a->Y; r->Z = a->Z; submod (&z, &a->T, &P, &r->T); }
static void pt_mul (const u256 *k, const pt *base, pt *r)
{
	pt acc; int i; pt_identity (&acc);
	for (i = 255; i >= 0; i--) { pt tmp; pt_add (&acc, &acc, &tmp); acc = tmp; if ((k->v[i >> 6] >> (i & 63)) & 1) { pt_add (&acc, base, &tmp); acc = tmp; } }
	*r = acc;
}
static void pt_compress (const pt *a, unsigned char out[32])
{
	u256 zi, x, y; int i;
	fe_inv (&a->Z, &zi);
	mulmod (&a->X, &zi, &P, &x); mulmod (&a->Y, &zi, &P, &y);
	for (i = 0; i < 32; i++) out[i] = (unsigned char) (y.v[i >> 3] >> ((i & 7) * 8));
	out[31] = (unsigned char) (out[31] | ((x.v[0] & 1) << 7));
}
static void load_le (const unsigned char *b, u256 *r)
{ int i; memset (r, 0, sizeof *r); for (i = 0; i < 32; i++) r->v[i >> 3] |= (uint64_t) b[i] << ((i & 7) * 8); }
static void clamp_scalar (const unsigned char seed[32], u256 *s)
{ unsigned char h[32]; memcpy (h, seed, 32); h[0] &= 248; h[31] &= 127; h[31] |= 64; load_le (h, s); }
static void share_of (const pt *K, unsigned char out[32])
{ unsigned char c[32]; pt_compress (K, c); sha256 (out, c, 32); }
static void phex (const char *label, const unsigned char *p, int n)
{ int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

/* ---- transport: read/write exactly n bytes over a stream socket ---- */
static int io_all (int fd, void *buf, size_t n, int writing)
{
	unsigned char *p = (unsigned char *) buf; size_t done = 0;
	while (done < n) {
		ssize_t r = writing ? write (fd, p + done, n - done) : read (fd, p + done, n - done);
		if (r <= 0) return -1;
		done += (size_t) r;
	}
	return 0;
}

/* ---- server process: holds s, answers Y = s*X for each X it is sent, until the socket closes ---- */
static void run_server (int fd, const u256 *s)
{
	pt X, Y;
	while (io_all (fd, &X, sizeof X, 0) == 0) {   /* receive blinded X (extended-coord wire form) */
		pt_mul (s, &X, &Y);                       /* the ONLY thing the server does: Y = s*X */
		if (io_all (fd, &Y, sizeof Y, 1) != 0) break;
	}
	close (fd);
	_exit (0);
}

/* ---- client unlock: X = C + e*G -> server -> Y ; K = Y - e*S ; returns 0 on success ---- */
static int client_unlock (int fd, const pt *C, const pt *S, const unsigned char eseed[32],
                          unsigned char shareOut[32], pt *xSentOut)
{
	u256 e; pt eG, X, Y, eS, negeS, K;
	clamp_scalar (eseed, &e);
	pt_base (&eG); pt_mul (&e, &eG, &eG);   /* e*G */
	pt_add (C, &eG, &X);                    /* X = C + e*G (blinded) */
	if (xSentOut) *xSentOut = X;
	if (io_all (fd, &X, sizeof X, 1) != 0) return -1;   /* off-network -> this fails */
	if (io_all (fd, &Y, sizeof Y, 0) != 0) return -1;
	pt_mul (&e, S, &eS); pt_neg (&eS, &negeS);
	pt_add (&Y, &negeS, &K);                /* K = Y - e*S = s*C */
	share_of (&K, shareOut);
	return 0;
}

int main (void)
{
	signal (SIGPIPE, SIG_IGN);   /* writing to the closed off-network peer must return EPIPE, not kill us */

	/* deterministic test scalars (seed bytes; clamped like an Ed25519 secret) */
	unsigned char sseed[32], cseed[32], e1[32], e2[32], sseed2[32];
	int i;
	for (i = 0; i < 32; i++) { sseed[i] = (unsigned char)(0x11*i+3); cseed[i] = (unsigned char)(0x07*i+9);
	                           e1[i] = (unsigned char)(0x2b*i+1); e2[i] = (unsigned char)(0x3d*i+5);
	                           sseed2[i] = (unsigned char)(0x55*i+2); }

	u256 s, c; clamp_scalar (sseed, &s); clamp_scalar (cseed, &c);
	pt G, S, C, cS;
	pt_base (&G);
	pt_mul (&s, &G, &S);        /* server public S = s*G */
	pt_mul (&c, &G, &C);        /* client   C = c*G  (goes in the recovery blob) */

	/* ENROLL: the share is K = c*S, computed offline once (no server round-trip). */
	unsigned char shareEnroll[32];
	pt_mul (&c, &S, &cS); share_of (&cS, shareEnroll);
	phex ("[C] enrolled share (c*S)       = ", shareEnroll, 32);

	/* The C-blob persisted by the client: { S, C }. (Serialized here as raw extended coords.) */
	struct { pt S, C; } blob = { S, C };

	/* ---- UNLOCK over a real socket to a forked server ---- */
	int sv[2];
	if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf ("socketpair failed\n"); return 1; }
	pid_t pid = fork ();
	if (pid == 0) { close (sv[0]); run_server (sv[1], &s); }   /* child = server */
	close (sv[1]);                                             /* parent = client */

	unsigned char share1[32], share2[32]; pt X1, X2;
	int r1 = client_unlock (sv[0], &blob.C, &blob.S, e1, share1, &X1);
	int r2 = client_unlock (sv[0], &blob.C, &blob.S, e2, share2, &X2);
	close (sv[0]);
	waitpid (pid, NULL, 0);

	phex ("[C] unlock share (over socket) = ", share1, 32);
	printf ("[C] unlock recovered enrolled share = %s\n",
	        (r1 == 0 && memcmp (share1, shareEnroll, 32) == 0) ? "YES" : "NO");
	printf ("[C] second unlock also recovers it  = %s\n",
	        (r2 == 0 && memcmp (share2, shareEnroll, 32) == 0) ? "YES" : "NO");

	/* the server saw only the blinded X, never C; and a fresh e makes X differ every unlock */
	printf ("[C] blinded X != stored C (server never sees C) = %s\n",
	        memcmp (&X1, &blob.C, sizeof (pt)) != 0 ? "YES" : "NO");
	printf ("[C] each unlock re-blinds (X1 != X2)            = %s\n",
	        memcmp (&X1, &X2, sizeof (pt)) != 0 ? "YES" : "NO");

	/* ---- OFF-NETWORK: no server to answer -> unlock cannot recover the share ---- */
	int svx[2]; socketpair (AF_UNIX, SOCK_STREAM, 0, svx);
	close (svx[1]);   /* nobody is listening: the peer is closed */
	unsigned char shareOff[32];
	int roff = client_unlock (svx[0], &blob.C, &blob.S, e1, shareOff, NULL);
	close (svx[0]);
	printf ("[C] off-network unlock fails (share unrecoverable) = %s\n", roff != 0 ? "YES" : "NO");

	/* ---- WRONG SERVER: a different secret s' answers -> different share ---- */
	u256 s2; clamp_scalar (sseed2, &s2);
	int sw[2]; socketpair (AF_UNIX, SOCK_STREAM, 0, sw);
	pid_t pid2 = fork ();
	if (pid2 == 0) { close (sw[0]); run_server (sw[1], &s2); }
	close (sw[1]);
	unsigned char shareWrong[32];
	int rw = client_unlock (sw[0], &blob.C, &blob.S, e1, shareWrong, NULL);
	close (sw[0]); waitpid (pid2, NULL, 0);
	printf ("[C] wrong-server share differs from enrolled     = %s\n",
	        (rw == 0 && memcmp (shareWrong, shareEnroll, 32) != 0) ? "YES" : "NO");

	int ok = (r1 == 0 && memcmp (share1, shareEnroll, 32) == 0)
	      && (r2 == 0 && memcmp (share2, shareEnroll, 32) == 0)
	      && memcmp (&X1, &blob.C, sizeof (pt)) != 0
	      && memcmp (&X1, &X2, sizeof (pt)) != 0
	      && roff != 0
	      && (rw == 0 && memcmp (shareWrong, shareEnroll, 32) != 0);
	printf ("NETSHARE TRANSPORT ROUND-TRIP %s\n", ok ? "PASSED" : "FAILED");
	return ok ? 0 : 1;
}
