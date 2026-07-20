/*
 * keyslotaf_test.c — AF-split keyslot records: the REAL AfSplit.c + Keyslot.c + KeyslotStore.c
 * (build_and_verify.sh step [36]; docs/AF-SPLIT-SPEC.md [FORMAT] integration).
 *
 * Two-way per the project convention: this drives the real compiled modules over an in-memory
 * KeyslotArea with a deterministic rng/KDF, emitting REF lines (full record bytes and properties)
 * that keyslotaf_reference.py recomputes independently (hashlib PBKDF2/HMAC + reimplemented
 * ChaCha20 + reimplemented AF diffuse). Behavioural lifecycle checks print PASS/FAIL lines.
 *
 * Record format under test (KeyslotStore.c): labeled v2 = magic ver=2 kdf rsv=s cost plen salt
 * ct[s*plen] tag; bare records stay field-free with ct[s*plen]. s is public config, like cost.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/AfSplit.h"
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* ---- test KDF: PBKDF2-HMAC-SHA256 over the real Sha2.c (matches keyslot_store_test.c) ---- */
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

/* ---- in-memory KeyslotArea (8 slots) + deterministic rng, both mirrored in python ---- */
#define AREA_SLOTS 8
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }

static uint32_t g_rng;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

#define VMK_LEN 64
#define PLEN (VMK_LEN + 1)
#define AF_S 4
#define L_CT_OFF 46   /* labeled record ct offset (KeyslotStore.c) */

static unsigned char VMK[VMK_LEN];

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-46s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

static void hexline (const char *name, const unsigned char *p, int n)
{
	int i;
	printf ("REF %s = ", name);
	for (i = 0; i < n; i++) printf ("%02x", p[i]);
	printf ("\n");
}

int main (void)
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char out[VMK_LEN]; int flags, idx, i;

	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	for (i=0;i<VMK_LEN;i++) VMK[i]=(unsigned char)(0x40+i);
	memset(&cfg, 0, sizeof(cfg));
	cfg.kdf=test_kdf; cfg.cost=256; cfg.vmkLen=VMK_LEN; cfg.maxSlots=AREA_SLOTS;
	cfg.randBytes=det_rand; cfg.afStripes=AF_S;

	/* ===== REF: deterministic labeled AF record (python recomputes byte-for-byte) ===== */
	memset(g_area, 0, sizeof(g_area));
	g_rng = 0xC0FFEEu;
	cfg.backend = KSB_HEADER;
	idx = KeyslotAdd(&cfg,&area,(const unsigned char*)"af-alice",8,0,VMK);
	printf("REF af labeled slot = %d\n", idx);
	hexline("af labeled record", g_area + (size_t)idx * KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
	memset(out,0,sizeof(out)); flags=-1;
	printf("REF af labeled roundtrip = %s\n",
	       (KeyslotOpen(&cfg,&area,(const unsigned char*)"af-alice",8,out,&flags)
	        && !memcmp(out,VMK,VMK_LEN) && flags==0) ? "YES" : "NO");
	printf("REF af labeled wrong pass rejected = %s\n",
	       !KeyslotOpen(&cfg,&area,(const unsigned char*)"af-alicf",8,out,&flags) ? "YES" : "NO");

	/* partial remnant: zero one stripe inside ct — the record must no longer open */
	{
		unsigned char save[PLEN];
		unsigned char *ct0 = g_area + (size_t)idx * KEYSLOT_TABLE_STRIDE + L_CT_OFF;
		memcpy(save, ct0, PLEN);
		memset(ct0, 0, PLEN);
		printf("REF af partial remnant defeated = %s\n",
		       !KeyslotOpen(&cfg,&area,(const unsigned char*)"af-alice",8,out,&flags) ? "YES" : "NO");
		memcpy(ct0, save, PLEN);
	}

	/* cfg/record stripe-count mismatch is rejected both ways (s is public config, like cost) */
	{
		KeyslotStoreCfg legacy = cfg; legacy.afStripes = 0;
		int no1 = !KeyslotOpen(&legacy,&area,(const unsigned char*)"af-alice",8,out,&flags);
		int idxL, no2;
		g_rng = 0xBEEFu;
		idxL = KeyslotAdd(&legacy,&area,(const unsigned char*)"leg-bob",7,0,VMK);
		no2 = !KeyslotOpen(&cfg,&area,(const unsigned char*)"leg-bob",7,out,&flags);
		printf("REF af cfg mismatch rejected = %s\n", (no1 && no2 && idxL>=0) ? "YES" : "NO");
		printf("REF af legacy coexists = %s\n",
		       (KeyslotOpen(&legacy,&area,(const unsigned char*)"leg-bob",7,out,&flags)
		        && KeyslotOpen(&cfg,&area,(const unsigned char*)"af-alice",8,out,&flags)) ? "YES" : "NO");
	}

	/* ===== REF: deterministic deniable (bare) AF record ===== */
	g_rng = 0xD0D0u;
	det_rand(g_area, sizeof(g_area));   /* fill with "random" so bare records blend in */
	cfg.backend = KSB_DENIABLE;
	idx = KeyslotAdd(&cfg,&area,(const unsigned char*)"af-denia",8,KEYSLOT_FLAG_DURESS,VMK);
	printf("REF af bare slot = %d\n", idx);
	hexline("af bare record", g_area + (size_t)idx * KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
	memset(out,0,sizeof(out)); flags=-1;
	printf("REF af bare roundtrip = %s\n",
	       (KeyslotOpen(&cfg,&area,(const unsigned char*)"af-denia",8,out,&flags)
	        && !memcmp(out,VMK,VMK_LEN) && flags==KEYSLOT_FLAG_DURESS) ? "YES" : "NO");

	/* ===== behavioural lifecycle with AF on (PASS/FAIL, not python-diffed) ===== */
	printf("[af lifecycle]\n");
	memset(g_area, 0, sizeof(g_area));
	g_rng = 0x5EED5EEDu;
	cfg.backend = KSB_HEADER;
	{
		int a = KeyslotAdd(&cfg,&area,(const unsigned char*)"alice",5,0,VMK);
		int b = KeyslotAdd(&cfg,&area,(const unsigned char*)"bob",3,KEYSLOT_FLAG_DURESS,VMK);
		check("af add A and B", a>=0 && b>=0 && a!=b);
		check("af count == 2", KeyslotCount(&cfg,&area)==2);
		check("af open A", KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags) && !memcmp(out,VMK,VMK_LEN) && flags==0);
		check("af open B (duress flag intact)", KeyslotOpen(&cfg,&area,(const unsigned char*)"bob",3,out,&flags) && flags==KEYSLOT_FLAG_DURESS);
		check("af revoke A", KeyslotRevoke(&cfg,&area,a)==0 && !KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags));
		check("af B survives revoke", KeyslotOpen(&cfg,&area,(const unsigned char*)"bob",3,out,&flags));
	}
	/* stripe count too large for the stride must be rejected up front */
	{
		KeyslotStoreCfg big = cfg; big.afStripes = 15;   /* 46 + 15*65 + 32 = 1053 > 1024 */
		check("af oversized stripe count rejected", KeyslotAdd(&big,&area,(const unsigned char*)"x",1,0,VMK) < 0);
	}

	printf("%s\n", all_pass ? "ALL AF KEYSLOT CHECKS PASSED" : "AF KEYSLOT CHECKS FAILED");
	return all_pass ? 0 : 1;
}
