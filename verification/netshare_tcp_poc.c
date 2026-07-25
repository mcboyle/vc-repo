/*
 * netshare_tcp_poc.c — the McCallum-Relyea network-share END TO END over REAL TCP between two hosts.
 *
 * netshare_transport_poc.c proved the MR exchange over a same-host AF_UNIX socketpair (forked server).
 * This is the "client transport" item from docs/NETWORK-SHARE-SPEC.md taken to a genuine two-machine
 * TCP transport: the server (secret s, answers Y = s*X) runs on one box, the client (blinds X = C+e*G,
 * recovers K = Y - e*S = c*S) runs on another and connects over the network. Same MR math and the same
 * from-scratch Ed25519 group as netshare_transport_poc.c / netshare_ed25519_poc.c, over the real Sha2.c.
 *
 * Modes:
 *   --server <port>          run the MR server with secret s   (Y = s*X for each X, until peer closes)
 *   --server-wrong <port>    run an MR server with a DIFFERENT secret s2 (the "wrong server")
 *   --client <host> <good> <wrong> <dead>   enroll offline, then over TCP assert:
 *       (1) share recovered from <host>:<good> == enrolled share (c*S), twice, with fresh blinding each;
 *       (2) blinded X != stored C and X1 != X2 (server never sees C; cannot correlate);
 *       (3) OFF-NETWORK: connecting to <host>:<dead> (nothing listening) cannot recover the share;
 *       (4) WRONG SERVER: <host>:<wrong> (secret s2) yields a DIFFERENT share.
 *   prints "NETSHARE TCP ROUND-TRIP PASSED/FAILED".
 *
 * Wire form: the raw extended-coordinate pt struct (as in the AF_UNIX POC); both hosts are x86-64 Linux,
 * so endianness matches — a production build would send compressed 32-byte points over HTTPS to a Tang
 * server (a serialization detail, called out honestly; this is validation, not shipping code).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
	for (i = 0; i < 4; i++) { c = 0; for (j = 0; j < 4; j++) { unsigned __int128 t = (unsigned __int128) a->v[i] * b->v[j] + prod[i + j] + c; prod[i + j] = (uint64_t) t; c = t >> 64; } prod[i + 4] += (uint64_t) c; }
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
	if (br) for (i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128) t.v[i] + m->v[i] + c; t.v[i] = (uint64_t) s; c = s >> 64; }
	*r = t;
}
static void powmod (const u256 *base, const u256 *exp, const u256 *m, u256 *r)
{ u256 res = { { 1, 0, 0, 0 } }, b = *base; int i; for (i = 255; i >= 0; i--) { mulmod (&res, &res, m, &res); if ((exp->v[i >> 6] >> (i & 63)) & 1) mulmod (&res, &b, m, &res); } *r = res; }
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
{ pt acc; int i; pt_identity (&acc); for (i = 255; i >= 0; i--) { pt tmp; pt_add (&acc, &acc, &tmp); acc = tmp; if ((k->v[i >> 6] >> (i & 63)) & 1) { pt_add (&acc, base, &tmp); acc = tmp; } } *r = acc; }
static void pt_compress (const pt *a, unsigned char out[32])
{ u256 zi, x, y; int i; fe_inv (&a->Z, &zi); mulmod (&a->X, &zi, &P, &x); mulmod (&a->Y, &zi, &P, &y); for (i = 0; i < 32; i++) out[i] = (unsigned char) (y.v[i >> 3] >> ((i & 7) * 8)); out[31] = (unsigned char) (out[31] | ((x.v[0] & 1) << 7)); }
static void load_le (const unsigned char *b, u256 *r)
{ int i; memset (r, 0, sizeof *r); for (i = 0; i < 32; i++) r->v[i >> 3] |= (uint64_t) b[i] << ((i & 7) * 8); }
static void clamp_scalar (const unsigned char seed[32], u256 *s)
{ unsigned char h[32]; memcpy (h, seed, 32); h[0] &= 248; h[31] &= 127; h[31] |= 64; load_le (h, s); }
static void share_of (const pt *K, unsigned char out[32]) { unsigned char c[32]; pt_compress (K, c); sha256 (out, c, 32); }
static void phex (const char *label, const unsigned char *p, int n) { int i; printf ("%s", label); for (i = 0; i < n; i++) printf ("%02x", p[i]); printf ("\n"); }

static int io_all (int fd, void *buf, size_t n, int writing)
{ unsigned char *p = (unsigned char *) buf; size_t done = 0; while (done < n) { ssize_t r = writing ? write (fd, p + done, n - done) : read (fd, p + done, n - done); if (r <= 0) return -1; done += (size_t) r; } return 0; }

/* deterministic test seeds — compiled into BOTH client and server so they agree on s / s2 / c. */
static void seeds (unsigned char sseed[32], unsigned char sseed2[32], unsigned char cseed[32],
                   unsigned char e1[32], unsigned char e2[32])
{ int i; for (i = 0; i < 32; i++) { sseed[i]=(unsigned char)(0x11*i+3); sseed2[i]=(unsigned char)(0x55*i+2);
	cseed[i]=(unsigned char)(0x07*i+9); e1[i]=(unsigned char)(0x2b*i+1); e2[i]=(unsigned char)(0x3d*i+5); } }

/* ---- TCP helpers ---- */
static int tcp_listen (int port)
{
	int fd = socket (AF_INET, SOCK_STREAM, 0), one = 1; struct sockaddr_in a;
	if (fd < 0) return -1;
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	memset (&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl (INADDR_ANY); a.sin_port = htons ((uint16_t) port);
	if (bind (fd, (struct sockaddr *) &a, sizeof a) != 0) { perror ("bind"); return -1; }
	if (listen (fd, 8) != 0) { perror ("listen"); return -1; }
	return fd;
}
static int tcp_connect (const char *host, int port)
{
	int fd = socket (AF_INET, SOCK_STREAM, 0); struct sockaddr_in a;
	if (fd < 0) return -1;
	memset (&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons ((uint16_t) port);
	if (inet_pton (AF_INET, host, &a.sin_addr) != 1) { close (fd); return -1; }
	if (connect (fd, (struct sockaddr *) &a, sizeof a) != 0) { close (fd); return -1; }
	return fd;
}

/* server: for each accepted client, answer Y = s*X until it closes. Runs until killed. */
static int run_server (int port, const unsigned char sseed[32])
{
	u256 s; clamp_scalar (sseed, &s);
	int lfd = tcp_listen (port); if (lfd < 0) return 1;
	fprintf (stderr, "netshare_tcp server: listening on :%d\n", port);
	for (;;) {
		int c = accept (lfd, NULL, NULL); if (c < 0) continue;
		pt X, Y;
		while (io_all (c, &X, sizeof X, 0) == 0) { pt_mul (&s, &X, &Y); if (io_all (c, &Y, sizeof Y, 1) != 0) break; }
		close (c);
	}
}

/* client unlock over a fresh TCP connection: returns 0 on success, fills share + the X it sent. */
static int client_unlock (const char *host, int port, const pt *C, const pt *S,
                          const unsigned char eseed[32], unsigned char shareOut[32], pt *xSentOut)
{
	u256 e; pt eG, X, Y, eS, negeS, K; int fd;
	clamp_scalar (eseed, &e);
	pt_base (&eG); pt_mul (&e, &eG, &eG);
	pt_add (C, &eG, &X);
	if (xSentOut) *xSentOut = X;
	fd = tcp_connect (host, port); if (fd < 0) return -1;         /* off-network / dead port -> fail */
	if (io_all (fd, &X, sizeof X, 1) != 0) { close (fd); return -1; }
	if (io_all (fd, &Y, sizeof Y, 0) != 0) { close (fd); return -1; }
	close (fd);
	pt_mul (&e, S, &eS); pt_neg (&eS, &negeS);
	pt_add (&Y, &negeS, &K);
	share_of (&K, shareOut);
	return 0;
}

int main (int argc, char **argv)
{
	unsigned char sseed[32], sseed2[32], cseed[32], e1[32], e2[32];
	signal (SIGPIPE, SIG_IGN);
	seeds (sseed, sseed2, cseed, e1, e2);

	if (argc >= 3 && strcmp (argv[1], "--server") == 0)       return run_server (atoi (argv[2]), sseed);
	if (argc >= 3 && strcmp (argv[1], "--server-wrong") == 0) return run_server (atoi (argv[2]), sseed2);

	if (argc >= 6 && strcmp (argv[1], "--client") == 0) {
		const char *host = argv[2]; int gp = atoi (argv[3]), wp = atoi (argv[4]), dp = atoi (argv[5]);
		u256 s, c; pt G, S, C, cS;
		clamp_scalar (sseed, &s); clamp_scalar (cseed, &c);
		pt_base (&G); pt_mul (&s, &G, &S); pt_mul (&c, &G, &C);   /* S public; C in the blob */
		unsigned char shareEnroll[32]; pt_mul (&c, &S, &cS); share_of (&cS, shareEnroll);
		phex ("[C] enrolled share (c*S)         = ", shareEnroll, 32);

		unsigned char sh1[32], sh2[32], shOff[32], shWrong[32]; pt X1, X2;
		int r1 = client_unlock (host, gp, &C, &S, e1, sh1, &X1);
		int r2 = client_unlock (host, gp, &C, &S, e2, sh2, &X2);
		int roff = client_unlock (host, dp, &C, &S, e1, shOff, NULL);
		int rw = client_unlock (host, wp, &C, &S, e1, shWrong, NULL);
		phex ("[C] unlock share (over TCP)      = ", sh1, 32);

		int a1 = (r1 == 0 && memcmp (sh1, shareEnroll, 32) == 0);
		int a2 = (r2 == 0 && memcmp (sh2, shareEnroll, 32) == 0);
		int a3 = (memcmp (&X1, &C, sizeof (pt)) != 0) && (memcmp (&X1, &X2, sizeof (pt)) != 0);
		int a4 = (roff != 0);
		int a5 = (rw == 0 && memcmp (shWrong, shareEnroll, 32) != 0);
		printf ("[C] unlock recovers enrolled share (TCP)         = %s\n", a1 ? "YES" : "NO");
		printf ("[C] second unlock recovers it (fresh blinding)   = %s\n", a2 ? "YES" : "NO");
		printf ("[C] blinded X != C and X1 != X2                  = %s\n", a3 ? "YES" : "NO");
		printf ("[C] off-network (dead port) unlock fails         = %s\n", a4 ? "YES" : "NO");
		printf ("[C] wrong-server share differs from enrolled     = %s\n", a5 ? "YES" : "NO");
		int ok = a1 && a2 && a3 && a4 && a5;
		printf ("NETSHARE TCP ROUND-TRIP %s\n", ok ? "PASSED" : "FAILED");
		return ok ? 0 : 1;
	}

	fprintf (stderr, "usage: %s --server <port> | --server-wrong <port> | --client <host> <good> <wrong> <dead>\n", argv[0]);
	return 2;
}
