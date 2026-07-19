/*
 * mlkem_poc.c — ML-KEM-768 (FIPS 203 final, Aug 2024) + PQ/classical hybrid
 * combiner. Post-quantum hedge for the network-bound share source: a
 * harvest-now-decrypt-later adversary who records the McCallum-Relyea/OPRF
 * exchange and later breaks the classical group must ALSO break ML-KEM to
 * recover the share, and vice versa (IND-CCA hedge both ways):
 *
 *   hybrid_tag = HMAC-SHA256(classical_ss || K_pq,
 *                            "VC-HYBRID-v1" || SHA256(ek) || SHA256(c))
 *
 * so neither secret alone determines the derived key material.
 *
 * ML-KEM-768: n=256 q=3329 k=3 eta1=eta2=2 du=10 dv=4, checked against the
 * official NIST ACVP FIPS-203 vectors (mlkem_kats.h): keyGen, encaps, and
 * decaps including the implicit-rejection (modified-ciphertext) cases. The
 * FIPS 202 sponge here is PoC-local (SHAKE squeeze needed); its SHA3-512 is
 * anchored to the REAL in-tree Crypto/Sha3.c (CHK line), and the SHA-256 /
 * HMAC-SHA256 sides drive the REAL in-tree Crypto/Sha2.c. mlkem_reference.py
 * is independent; build_and_verify.sh diffs REF lines byte-for-byte.
 *
 * Honest note: this is a correctness PoC — plain uint16/uint32 arithmetic with
 * `% q`, not constant-time, not side-channel hardened. A production build would
 * ship a vetted constant-time ML-KEM implementation; this file establishes the
 * algorithm, the vectors, and the hybrid seam.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Crypto/Sha3.h"
#include "Crypto/Sha2.h"
#include "mlkem_kats.h"

#define Q     3329
#define KK    3
#define EKLEN 1184
#define DKLEN 2400
#define CLEN  1088

/* ---------- PoC-local Keccak-f[1600] sponge (SHA3/SHAKE) ---------- */

static const uint64_t kc_rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL };
static const int kc_rho[24] = { 1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44 };
static const int kc_pi[24]  = { 10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1 };

static uint64_t kc_rotl (uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

static void kc_permute (uint64_t st[25])
{
	uint64_t bc[5], t;
	int r, i, j;
	for (r = 0; r < 24; r++) {
		for (i = 0; i < 5; i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
		for (i = 0; i < 5; i++) {
			t = bc[(i+4)%5] ^ kc_rotl (bc[(i+1)%5], 1);
			for (j = 0; j < 25; j += 5) st[j+i] ^= t;
		}
		t = st[1];
		for (i = 0; i < 24; i++) { j = kc_pi[i]; bc[0] = st[j]; st[j] = kc_rotl (t, kc_rho[i]); t = bc[0]; }
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++) bc[i] = st[j+i];
			for (i = 0; i < 5; i++) st[j+i] = bc[i] ^ ((~bc[(i+1)%5]) & bc[(i+2)%5]);
		}
		st[0] ^= kc_rc[r];
	}
}

typedef struct { uint64_t st[25]; unsigned rate, pos; } kc_sponge;

static void kc_init (kc_sponge *s, unsigned rate) { memset (s, 0, sizeof *s); s->rate = rate; }

static void kc_absorb (kc_sponge *s, const unsigned char *in, size_t n)
{
	while (n--) {
		s->st[s->pos >> 3] ^= (uint64_t) *in++ << (8 * (s->pos & 7));
		if (++s->pos == s->rate) { kc_permute (s->st); s->pos = 0; }
	}
}

static void kc_pad (kc_sponge *s, unsigned char dom)
{
	s->st[s->pos >> 3] ^= (uint64_t) dom << (8 * (s->pos & 7));
	s->st[(s->rate - 1) >> 3] ^= 0x80ULL << (8 * ((s->rate - 1) & 7));
	kc_permute (s->st);
	s->pos = 0;
}

static void kc_squeeze (kc_sponge *s, unsigned char *out, size_t n)
{
	while (n--) {
		if (s->pos == s->rate) { kc_permute (s->st); s->pos = 0; }
		*out++ = (unsigned char) (s->st[s->pos >> 3] >> (8 * (s->pos & 7)));
		s->pos++;
	}
}

static void kc_hash (unsigned rate, unsigned char dom, const unsigned char *in, size_t n,
                     unsigned char *out, size_t outlen)
{
	kc_sponge s;
	kc_init (&s, rate);
	kc_absorb (&s, in, n);
	kc_pad (&s, dom);
	kc_squeeze (&s, out, outlen);
}

/* H, G, J of FIPS 203 */
static void h_sha3_256 (const unsigned char *in, size_t n, unsigned char out[32])
{ kc_hash (136, 0x06, in, n, out, 32); }
static void g_sha3_512 (const unsigned char *in, size_t n, unsigned char out[64])
{ kc_hash (72, 0x06, in, n, out, 64); }
static void j_shake256 (const unsigned char *in, size_t n, unsigned char out[32])
{ kc_hash (136, 0x1f, in, n, out, 32); }

/* ---------- SHA-256 / HMAC-SHA256 over the REAL in-tree Crypto/Sha2.c ---------- */

static void sha256_d (const unsigned char *m, size_t n, unsigned char out[32])
{ sha256_ctx c; sha256_begin (&c); if (n) sha256_hash (m, (uint_32t) n, &c); sha256_end (out, &c); }

static void hmac_sha256_d (const unsigned char *key, size_t klen,
                           const unsigned char *msg, size_t mlen, unsigned char out[32])
{
	unsigned char k[64], ipad[64], opad[64], inner[32];
	sha256_ctx c; int i;
	memset (k, 0, 64);
	if (klen > 64) sha256_d (key, klen, k); else memcpy (k, key, klen);
	for (i = 0; i < 64; i++) { ipad[i] = (unsigned char) (k[i] ^ 0x36); opad[i] = (unsigned char) (k[i] ^ 0x5c); }
	sha256_begin (&c); sha256_hash (ipad, 64, &c); if (mlen) sha256_hash (msg, (uint_32t) mlen, &c); sha256_end (inner, &c);
	sha256_begin (&c); sha256_hash (opad, 64, &c); sha256_hash (inner, 32, &c); sha256_end (out, &c);
}

/* ---------- ML-KEM-768 polynomial layer ---------- */

static uint16_t zetas[128];   /* 17^BitRev7(i) mod q  */
static uint16_t gammas[128];  /* 17^(2*BitRev7(i)+1)  */

static int bitrev7 (int i)
{ int r = 0, b; for (b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b); return r; }

static uint16_t pow_q (uint16_t base, int e)
{ uint32_t r = 1, b = base; while (e) { if (e & 1) r = r * b % Q; b = b * b % Q; e >>= 1; } return (uint16_t) r; }

static void init_zetas (void)
{
	int i;
	for (i = 0; i < 128; i++) {
		zetas[i]  = pow_q (17, bitrev7 (i));
		gammas[i] = pow_q (17, 2 * bitrev7 (i) + 1);
	}
}

static void ntt (uint16_t f[256])
{
	int len, start, j, i = 1;
	uint32_t z, t;
	for (len = 128; len >= 2; len >>= 1)
		for (start = 0; start < 256; start += 2 * len) {
			z = zetas[i++];
			for (j = start; j < start + len; j++) {
				t = z * f[j+len] % Q;
				f[j+len] = (uint16_t) ((f[j] + Q - t) % Q);
				f[j]     = (uint16_t) ((f[j] + t) % Q);
			}
		}
}

static void intt (uint16_t f[256])
{
	int len, start, j, i = 127;
	uint32_t z, t;
	for (len = 2; len <= 128; len <<= 1)
		for (start = 0; start < 256; start += 2 * len) {
			z = zetas[i--];
			for (j = start; j < start + len; j++) {
				t = f[j];
				f[j]     = (uint16_t) ((t + f[j+len]) % Q);
				f[j+len] = (uint16_t) (z * ((f[j+len] + Q - t) % Q) % Q);
			}
		}
	for (j = 0; j < 256; j++) f[j] = (uint16_t) ((uint32_t) f[j] * 3303 % Q);  /* 128^-1 mod q */
}

static void basemul (const uint16_t a[256], const uint16_t b[256], uint16_t c[256])
{
	int i;
	for (i = 0; i < 128; i++) {
		uint32_t g = gammas[i];
		c[2*i]   = (uint16_t) (((uint32_t) a[2*i] * b[2*i] + (uint32_t) a[2*i+1] * b[2*i+1] % Q * g) % Q);
		c[2*i+1] = (uint16_t) (((uint32_t) a[2*i] * b[2*i+1] + (uint32_t) a[2*i+1] * b[2*i]) % Q);
	}
}

static void poly_add (uint16_t a[256], const uint16_t b[256])
{ int i; for (i = 0; i < 256; i++) a[i] = (uint16_t) ((a[i] + b[i]) % Q); }

static void sample_ntt (const unsigned char rho[32], unsigned char jb, unsigned char ib, uint16_t f[256])
{
	kc_sponge s;
	unsigned char b[3];
	int n = 0;
	kc_init (&s, 168);                      /* SHAKE128 XOF */
	kc_absorb (&s, rho, 32);
	kc_absorb (&s, &jb, 1);
	kc_absorb (&s, &ib, 1);
	kc_pad (&s, 0x1f);
	while (n < 256) {
		uint16_t d1, d2;
		kc_squeeze (&s, b, 3);
		d1 = (uint16_t) (b[0] + 256 * (b[1] & 15));
		d2 = (uint16_t) ((b[1] >> 4) + 16 * b[2]);
		if (d1 < Q) f[n++] = d1;
		if (d2 < Q && n < 256) f[n++] = d2;
	}
}

/* PRF_eta(s, b) = SHAKE256(s || byte(b), 64*eta); eta1 = eta2 = 2 here */
static void prf_eta2 (const unsigned char s[32], unsigned char b, unsigned char out[128])
{
	kc_sponge sp;
	kc_init (&sp, 136);
	kc_absorb (&sp, s, 32);
	kc_absorb (&sp, &b, 1);
	kc_pad (&sp, 0x1f);
	kc_squeeze (&sp, out, 128);
}

static void cbd_eta2 (const unsigned char B[128], uint16_t f[256])
{
	int i;
	for (i = 0; i < 256; i++) {
		int x = ((B[(4*i)   >> 3] >> ((4*i)   & 7)) & 1) + ((B[(4*i+1) >> 3] >> ((4*i+1) & 7)) & 1);
		int y = ((B[(4*i+2) >> 3] >> ((4*i+2) & 7)) & 1) + ((B[(4*i+3) >> 3] >> ((4*i+3) & 7)) & 1);
		f[i] = (uint16_t) ((x - y + Q) % Q);
	}
}

static uint16_t compress_d (uint16_t x, int d)
{ return (uint16_t) (((((uint32_t) x << d) + 1664) / 3329) & ((1u << d) - 1)); }

static uint16_t decompress_d (uint16_t y, int d)
{ return (uint16_t) (((uint32_t) y * 3329 + (1u << (d - 1))) >> d); }

/* d bits per coefficient, LSB-first, into an LSB-first-packed bitstream */
static void byte_encode (const uint16_t f[256], int d, unsigned char *out)
{
	int i, b, pos = 0;
	memset (out, 0, (size_t) (32 * d));
	for (i = 0; i < 256; i++)
		for (b = 0; b < d; b++, pos++)
			if ((f[i] >> b) & 1) out[pos >> 3] |= (unsigned char) (1 << (pos & 7));
}

static void byte_decode (const unsigned char *in, int d, uint16_t f[256])
{
	int i, b, pos = 0;
	for (i = 0; i < 256; i++) {
		uint16_t v = 0;
		for (b = 0; b < d; b++, pos++)
			v |= (uint16_t) (((in[pos >> 3] >> (pos & 7)) & 1) << b);
		f[i] = v;
	}
}

/* ---------- K-PKE ---------- */

static void gen_matrix (const unsigned char rho[32], uint16_t A[KK][KK][256])
{
	int i, j;
	for (i = 0; i < KK; i++)
		for (j = 0; j < KK; j++)   /* XOF input is rho || byte(j) || byte(i) */
			sample_ntt (rho, (unsigned char) j, (unsigned char) i, A[i][j]);
}

static void pke_keygen (const unsigned char d[32], unsigned char ek[EKLEN], unsigned char dkp[1152])
{
	unsigned char gin[33], gh[64], buf[128];
	static uint16_t A[KK][KK][256];
	uint16_t s[KK][256], e[KK][256], t[256], acc[256];
	int i, j, N = 0;

	memcpy (gin, d, 32);
	gin[32] = (unsigned char) KK;           /* FIPS 203 final: G(d || byte(k)) */
	g_sha3_512 (gin, 33, gh);               /* rho = gh[0:32], sigma = gh[32:64] */
	gen_matrix (gh, A);
	for (i = 0; i < KK; i++) { prf_eta2 (gh + 32, (unsigned char) N++, buf); cbd_eta2 (buf, s[i]); }
	for (i = 0; i < KK; i++) { prf_eta2 (gh + 32, (unsigned char) N++, buf); cbd_eta2 (buf, e[i]); }
	for (i = 0; i < KK; i++) { ntt (s[i]); ntt (e[i]); }
	for (i = 0; i < KK; i++) {
		memcpy (acc, e[i], sizeof acc);
		for (j = 0; j < KK; j++) { basemul (A[i][j], s[j], t); poly_add (acc, t); }
		byte_encode (acc, 12, ek + 384 * i);
	}
	memcpy (ek + 1152, gh, 32);             /* || rho */
	for (i = 0; i < KK; i++) byte_encode (s[i], 12, dkp + 384 * i);
}

static void pke_encrypt (const unsigned char ek[EKLEN], const unsigned char m[32],
                         const unsigned char r[32], unsigned char c[CLEN])
{
	static uint16_t A[KK][KK][256];
	uint16_t t_hat[KK][256], y[KK][256], e1[KK][256], e2[256];
	uint16_t acc[256], tmp[256], cf[256];
	unsigned char buf[128];
	int i, j, N = 0;

	for (i = 0; i < KK; i++) byte_decode (ek + 384 * i, 12, t_hat[i]);
	gen_matrix (ek + 1152, A);
	for (i = 0; i < KK; i++) { prf_eta2 (r, (unsigned char) N++, buf); cbd_eta2 (buf, y[i]); }
	for (i = 0; i < KK; i++) { prf_eta2 (r, (unsigned char) N++, buf); cbd_eta2 (buf, e1[i]); }
	prf_eta2 (r, (unsigned char) N++, buf); cbd_eta2 (buf, e2);
	for (i = 0; i < KK; i++) ntt (y[i]);

	for (i = 0; i < KK; i++) {              /* u[i] = INTT(sum_j A[j][i]*y[j]) + e1[i] — transposed A */
		memset (acc, 0, sizeof acc);
		for (j = 0; j < KK; j++) { basemul (A[j][i], y[j], tmp); poly_add (acc, tmp); }
		intt (acc);
		poly_add (acc, e1[i]);
		for (j = 0; j < 256; j++) cf[j] = compress_d (acc[j], 10);
		byte_encode (cf, 10, c + 320 * i);
	}

	memset (acc, 0, sizeof acc);            /* v = INTT(sum_j t_hat[j]*y[j]) + e2 + mu */
	for (j = 0; j < KK; j++) { basemul (t_hat[j], y[j], tmp); poly_add (acc, tmp); }
	intt (acc);
	poly_add (acc, e2);
	byte_decode (m, 1, tmp);
	for (j = 0; j < 256; j++) tmp[j] = decompress_d (tmp[j], 1);
	poly_add (acc, tmp);
	for (j = 0; j < 256; j++) cf[j] = compress_d (acc[j], 4);
	byte_encode (cf, 4, c + 960);
}

static void pke_decrypt (const unsigned char dkp[1152], const unsigned char c[CLEN], unsigned char m[32])
{
	uint16_t sh[256], up[256], vp[256], acc[256], tmp[256];
	int i, j;

	memset (acc, 0, sizeof acc);
	for (j = 0; j < KK; j++) {
		byte_decode (c + 320 * j, 10, up);
		for (i = 0; i < 256; i++) up[i] = decompress_d (up[i], 10);
		ntt (up);
		byte_decode (dkp + 384 * j, 12, sh);
		basemul (sh, up, tmp);
		poly_add (acc, tmp);
	}
	intt (acc);
	byte_decode (c + 960, 4, vp);
	for (i = 0; i < 256; i++) vp[i] = decompress_d (vp[i], 4);
	for (i = 0; i < 256; i++) tmp[i] = (uint16_t) ((vp[i] + Q - acc[i]) % Q);   /* w = v' - s^T u' */
	for (i = 0; i < 256; i++) tmp[i] = compress_d (tmp[i], 1);
	byte_encode (tmp, 1, m);
}

/* ---------- ML-KEM ---------- */

static void kem_keygen (const unsigned char d[32], const unsigned char z[32],
                        unsigned char ek[EKLEN], unsigned char dk[DKLEN])
{
	pke_keygen (d, ek, dk);                 /* dk[0:1152] = dk_pke */
	memcpy (dk + 1152, ek, EKLEN);
	h_sha3_256 (ek, EKLEN, dk + 2336);
	memcpy (dk + 2368, z, 32);
}

static void kem_encaps (const unsigned char ek[EKLEN], const unsigned char m[32],
                        unsigned char K[32], unsigned char c[CLEN])
{
	unsigned char gin[64], gh[64];
	memcpy (gin, m, 32);
	h_sha3_256 (ek, EKLEN, gin + 32);
	g_sha3_512 (gin, 64, gh);               /* K = gh[0:32], r = gh[32:64] */
	memcpy (K, gh, 32);
	pke_encrypt (ek, m, gh + 32, c);
}

/* returns 1 if the implicit-rejection branch was taken */
static int kem_decaps (const unsigned char dk[DKLEN], const unsigned char c[CLEN], unsigned char K[32])
{
	unsigned char m1[32], gin[64], gh[64], kbar[32], c1[CLEN];
	static unsigned char jin[32 + CLEN];

	pke_decrypt (dk, c, m1);
	memcpy (gin, m1, 32);
	memcpy (gin + 32, dk + 2336, 32);       /* h = H(ek), stored in dk */
	g_sha3_512 (gin, 64, gh);
	memcpy (jin, dk + 2368, 32);            /* z */
	memcpy (jin + 32, c, CLEN);
	j_shake256 (jin, 32 + CLEN, kbar);
	pke_encrypt (dk + 1152, m1, gh + 32, c1);
	if (memcmp (c, c1, CLEN) != 0) { memcpy (K, kbar, 32); return 1; }
	memcpy (K, gh, 32);
	return 0;
}

/* ---------- vector plumbing ---------- */

static int hexval (char ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return -1;
}

static size_t hex2bin (const char *h, unsigned char *out, size_t max)
{
	size_t n = 0;
	while (h[0] && h[1] && n < max) {
		int hi = hexval (h[0]), lo = hexval (h[1]);
		if (hi < 0 || lo < 0) break;
		out[n++] = (unsigned char) ((hi << 4) | lo);
		h += 2;
	}
	return n;
}

static void print_hex (const unsigned char *b, size_t n)
{ size_t i; for (i = 0; i < n; i++) printf ("%02x", b[i]); }

int main (void)
{
	static unsigned char ek[EKLEN], dk[DKLEN], ek_off[EKLEN], dk_off[DKLEN];
	static unsigned char c[CLEN], c_off[CLEN];
	unsigned char d32[32], z32[32], m32[32], k32[32], k_off[32], dig[32];
	int i, ok, all_ok = 1, rejections = 0;

	init_zetas ();

	/* anchor the PoC-local SHA3-512 to the REAL in-tree Crypto/Sha3.c */
	{
		static const size_t lens[6] = { 0, 1, 71, 72, 73, 200 };
		unsigned char buf[200], a[64], b[64];
		size_t li;
		SHA3_CTX ctx;
		for (li = 0; li < sizeof buf; li++) buf[li] = (unsigned char) ((li * 3 + 1) & 0xff);
		ok = 1;
		for (li = 0; li < 6; li++) {
			g_sha3_512 (buf, lens[li], a);
			sha3_512_init (&ctx);
			sha3_512_update (&ctx, buf, lens[li]);
			sha3_512_final (&ctx, b);
			if (memcmp (a, b, 64) != 0) ok = 0;
		}
		printf ("CHK sha3_512_intree_match %s\n", ok ? "YES" : "NO");
		if (!ok) all_ok = 0;
	}

	/* keyGen against official ACVP vectors */
	ok = 1;
	for (i = 0; i < MLKEM_NKEYGEN; i++) {
		hex2bin (mlkem_keygen[i][0], d32, 32);
		hex2bin (mlkem_keygen[i][1], z32, 32);
		hex2bin (mlkem_keygen[i][2], ek_off, EKLEN);
		hex2bin (mlkem_keygen[i][3], dk_off, DKLEN);
		kem_keygen (d32, z32, ek, dk);
		sha256_d (ek, EKLEN, dig);
		printf ("REF keygen_%d_ek_sha256 ", i); print_hex (dig, 32); printf ("\n");
		sha256_d (dk, DKLEN, dig);
		printf ("REF keygen_%d_dk_sha256 ", i); print_hex (dig, 32); printf ("\n");
		if (memcmp (ek, ek_off, EKLEN) != 0 || memcmp (dk, dk_off, DKLEN) != 0) ok = 0;
	}
	printf ("REF keygen_all_match %s\n", ok ? "YES" : "NO");
	if (!ok) all_ok = 0;

	/* encaps against official ACVP vectors */
	ok = 1;
	for (i = 0; i < MLKEM_NENCAPS; i++) {
		hex2bin (mlkem_encaps[i][0], ek, EKLEN);
		hex2bin (mlkem_encaps[i][1], m32, 32);
		hex2bin (mlkem_encaps[i][2], c_off, CLEN);
		hex2bin (mlkem_encaps[i][3], k_off, 32);
		kem_encaps (ek, m32, k32, c);
		sha256_d (c, CLEN, dig);
		printf ("REF encaps_%d_c_sha256 ", i); print_hex (dig, 32); printf ("\n");
		printf ("REF encaps_%d_k ", i); print_hex (k32, 32); printf ("\n");
		if (memcmp (c, c_off, CLEN) != 0 || memcmp (k32, k_off, 32) != 0) ok = 0;
	}
	printf ("REF encaps_all_match %s\n", ok ? "YES" : "NO");
	if (!ok) all_ok = 0;

	/* decaps, including the implicit-rejection (modified-ciphertext) cases */
	ok = 1;
	for (i = 0; i < MLKEM_NDECAPS; i++) {
		hex2bin (mlkem_decaps[i][0], dk, DKLEN);
		hex2bin (mlkem_decaps[i][1], c, CLEN);
		hex2bin (mlkem_decaps[i][2], k_off, 32);
		rejections += kem_decaps (dk, c, k32);
		printf ("REF decaps_%d_k ", i); print_hex (k32, 32); printf ("\n");
		if (memcmp (k32, k_off, 32) != 0) ok = 0;
	}
	printf ("REF decaps_all_match %s\n", ok ? "YES" : "NO");
	if (!ok) all_ok = 0;
	printf ("REF implicit_rejection_cases %d\n", rejections);
	if (rejections != 5) all_ok = 0;

	/* hybrid combiner over official encaps vector 0 (classical_ss stands in
	   for the McCallum-Relyea/OPRF exchange output) */
	{
		unsigned char cls[32], key[64], msg[12 + 32 + 32], tag[32], tag2[32], tag3[32];
		int both;
		hex2bin (mlkem_encaps[0][0], ek, EKLEN);
		hex2bin (mlkem_encaps[0][2], c, CLEN);
		hex2bin (mlkem_encaps[0][3], k32, 32);
		for (i = 0; i < 32; i++) cls[i] = (unsigned char) ((i * 7 + 1) & 0xff);
		memcpy (msg, "VC-HYBRID-v1", 12);
		sha256_d (ek, EKLEN, msg + 12);
		sha256_d (c, CLEN, msg + 44);
		memcpy (key, cls, 32); memcpy (key + 32, k32, 32);
		hmac_sha256_d (key, 64, msg, sizeof msg, tag);
		printf ("REF hybrid_tag "); print_hex (tag, 32); printf ("\n");
		key[0] ^= 1;                                    /* flip bit0 of classical_ss */
		hmac_sha256_d (key, 64, msg, sizeof msg, tag2);
		key[0] ^= 1; key[32] ^= 1;                      /* flip bit0 of K_pq instead */
		hmac_sha256_d (key, 64, msg, sizeof msg, tag3);
		both = memcmp (tag, tag2, 32) != 0 && memcmp (tag, tag3, 32) != 0;
		printf ("REF hybrid_needs_both %s\n", both ? "YES" : "NO");
		if (!both) all_ok = 0;
	}

	return all_ok ? 0 : 1;
}
