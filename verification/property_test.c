/*
 * property_test.c — degenerate-input property tests (ROI item 35).
 *
 * Step [45] does broad seeded/differential fuzzing; this pins down the specific DEGENERATE cases a
 * random fuzzer rarely hits reliably and that historically break threshold schemes and passphrase
 * handling: threshold == n_shares, threshold == 2 boundaries, DUPLICATE x-coordinates (a Lagrange
 * divide-by-zero if unguarded), parameter-range rejection, and ZERO-LENGTH passwords in the keyslot
 * path. Each is an explicit property with a known outcome, driving the REAL Shamir.c / KeyslotStore.c.
 * Built (in the suite) under ASan+UBSan so a divide-by-zero / OOB in a degenerate case is also caught.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Shamir.h"
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

static int all_pass = 1;
static void check (const char *name, int ok) { printf ("  %-56s %s\n", name, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }

static uint64_t g_s = 0xabcdef0123456789ULL;
static uint64_t xr (void) { uint64_t x=g_s; x^=x<<13; x^=x>>7; x^=x<<17; g_s=x; return x; }

/* ---- test KDF (PBKDF2-HMAC-SHA256, same as the other keyslot harnesses) ---- */
#define BLK 64
#define DIG 32
static void hmac256 (const unsigned char *k, int kl, const unsigned char *m, int ml, unsigned char o[DIG])
{
	sha256_ctx c; unsigned char k0[BLK], p[BLK], in[DIG]; int i;
	if (kl > BLK) { sha256_begin(&c); sha256_hash(k,(unsigned)kl,&c); sha256_end(k0,&c); memset(k0+DIG,0,BLK-DIG); }
	else { if (kl>0) memcpy(k0,k,kl); memset(k0+kl,0,BLK-kl); }
	for (i=0;i<BLK;i++) p[i]=k0[i]^0x36;
	sha256_begin(&c); sha256_hash(p,BLK,&c); if (ml>0) sha256_hash(m,(unsigned)ml,&c); sha256_end(in,&c);
	for (i=0;i<BLK;i++) p[i]=k0[i]^0x5c;
	sha256_begin(&c); sha256_hash(p,BLK,&c); sha256_hash(in,DIG,&c); sha256_end(o,&c);
}
static void test_kdf (const unsigned char *pw, int pwl, const unsigned char *salt, int sl,
                      unsigned int iters, unsigned char *out, int outLen)
{
	int blocks=(outLen+DIG-1)/DIG, blk, i; unsigned char T[DIG],U[DIG],sb[128+4];
	for (blk=1; blk<=blocks; blk++) {
		unsigned int j; int k;
		memcpy(sb,salt,sl); sb[sl]=(unsigned char)(blk>>24); sb[sl+1]=(unsigned char)(blk>>16);
		sb[sl+2]=(unsigned char)(blk>>8); sb[sl+3]=(unsigned char)blk;
		hmac256(pw,pwl,sb,sl+4,U); memcpy(T,U,DIG);
		for (j=1;j<iters;j++){ hmac256(pw,pwl,U,DIG,U); for(k=0;k<DIG;k++) T[k]^=U[k]; }
		{ int off=(blk-1)*DIG, n=(outLen-off<DIG)?(outLen-off):DIG; for(i=0;i<n;i++) out[off+i]=T[i]; }
	}
}
#define AREA_SLOTS 8
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++) p[i]=(unsigned char) xr(); }

int main (void)
{
	unsigned char secret[SHAMIR_MAX_SECRET], rnd[SHAMIR_MAX_SHARES*SHAMIR_MAX_SECRET], rec[SHAMIR_MAX_SECRET];
	ShamirShare sh[SHAMIR_MAX_SHARES];
	int L = 32, i, rl;

	for (i = 0; i < L; i++) secret[i] = (unsigned char)(0x10 + i);
	for (i = 0; i < (int)sizeof(rnd); i++) rnd[i] = (unsigned char) xr();

	printf ("[shamir degenerate thresholds]\n");
	/* t == n: all n reconstruct; any n-1 do NOT (by design, wrong secret) */
	{
		int n = 5, t = 5, ok;
		ShamirShare few[4];
		ok = shamir_split (secret, L, t, n, rnd, sh) == SHAMIR_OK;
		check ("t==n split ok", ok);
		check ("t==n: all n shares reconstruct", shamir_combine (sh, n, rec, &rl) == SHAMIR_OK && rl == L && !memcmp (rec, secret, L));
		for (i = 0; i < 4; i++) few[i] = sh[i];
		shamir_combine (few, 4, rec, &rl);
		check ("t==n: n-1 shares do NOT recover the secret", memcmp (rec, secret, L) != 0);
	}
	/* t == 2: any single share does NOT recover; any 2 do */
	{
		int n = 4, t = 2;
		check ("t==2 split ok", shamir_split (secret, L, t, n, rnd, sh) == SHAMIR_OK);
		{ ShamirShare one[1]; one[0] = sh[2]; shamir_combine (one, 1, rec, &rl); check ("t==2: 1 share does NOT recover", memcmp (rec, secret, L) != 0); }
		{ ShamirShare two[2]; two[0] = sh[1]; two[1] = sh[3]; check ("t==2: any 2 shares recover", shamir_combine (two, 2, rec, &rl) == SHAMIR_OK && !memcmp (rec, secret, L)); }
	}

	printf ("[shamir duplicate x-coordinates]\n");
	/* two shares with the SAME x -> Lagrange denominator (x_i ^ x_j) == 0. Must be rejected, not a
	   divide-by-zero / gf_inv(0). (Run under UBSan in the suite, so an unguarded case would also trap.) */
	{
		ShamirShare dup[3];
		shamir_split (secret, L, 3, 5, rnd, sh);
		dup[0] = sh[0]; dup[1] = sh[1]; dup[2] = sh[1];   /* sh[1] repeated -> duplicate x */
		check ("duplicate x-coords rejected (SHAMIR_ERR_PARAM)", shamir_combine (dup, 3, rec, &rl) == SHAMIR_ERR_PARAM);
	}

	printf ("[shamir parameter range]\n");
	check ("threshold < 2 rejected",      shamir_split (secret, L, 1, 5, rnd, sh) == SHAMIR_ERR_PARAM);
	check ("threshold > n rejected",      shamir_split (secret, L, 6, 5, rnd, sh) == SHAMIR_ERR_PARAM);
	check ("n > SHAMIR_MAX_SHARES rejected", shamir_split (secret, L, 2, SHAMIR_MAX_SHARES + 1, rnd, sh) == SHAMIR_ERR_PARAM);
	check ("secret_len 0 rejected",       shamir_split (secret, 0, 2, 3, rnd, sh) == SHAMIR_ERR_PARAM);
	check ("secret_len > MAX rejected",   shamir_split (secret, SHAMIR_MAX_SECRET + 1, 2, 3, rnd, sh) == SHAMIR_ERR_PARAM);

	printf ("[shamir boundary secrets]\n");
	{
		unsigned char z[SHAMIR_MAX_SECRET], f[SHAMIR_MAX_SECRET];
		memset (z, 0x00, L); memset (f, 0xff, L);
		shamir_split (z, L, 3, 5, rnd, sh);   check ("all-zero secret round-trips", shamir_combine (sh, 3, rec, &rl) == SHAMIR_OK && !memcmp (rec, z, L));
		shamir_split (f, L, 3, 5, rnd, sh);   check ("all-0xFF secret round-trips", shamir_combine (sh, 3, rec, &rl) == SHAMIR_OK && !memcmp (rec, f, L));
		{ int one = 1; unsigned char s1[1] = {0xA5}, r1[1]; shamir_split (s1, one, 2, 3, rnd, sh); check ("1-byte secret round-trips", shamir_combine (sh, 2, r1, &rl) == SHAMIR_OK && rl == 1 && r1[0] == 0xA5); }
	}

	printf ("[keyslot zero-length password]\n");
	{
		KeyslotArea area; KeyslotStoreCfg cfg; unsigned char vmk[64], out[64]; int flags = -1, idx;
		for (i = 0; i < 64; i++) vmk[i] = (unsigned char)(0x40 + i);
		area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
		memset (&cfg, 0, sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=64; cfg.vmkLen=64; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand;
		cfg.backend = KSB_HEADER; memset (g_area, 0, sizeof(g_area));
		idx = KeyslotAdd (&cfg, &area, (const unsigned char*)"", 0, 0, vmk);
		check ("add slot with zero-length password", idx >= 0);
		check ("zero-length password opens it + recovers VMK", KeyslotOpen (&cfg,&area,(const unsigned char*)"",0,out,&flags) && !memcmp (out, vmk, 64));
		check ("a non-empty password does NOT open the empty-password slot", !KeyslotOpen (&cfg,&area,(const unsigned char*)"x",1,out,&flags));
		memset (g_area, 0, sizeof(g_area));
		check ("open on an empty area returns no-match (no crash)", KeyslotOpen (&cfg,&area,(const unsigned char*)"",0,out,&flags) == 0);
	}

	printf ("\n%s\n", all_pass ? "PASS: degenerate-input properties hold (thresholds, duplicate-x, ranges, zero-length password)"
	                            : "FAIL: property tests");
	return all_pass ? 0 : 1;
}
