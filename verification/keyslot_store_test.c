/*
 * keyslot_store_test.c — end-to-end lifecycle test of the REAL Keyslot.c + KeyslotStore.c.
 *
 * The per-slot wrapping crypto is proven two ways in keyslot_poc.c (build_and_verify.sh step [8]).
 * This harness exercises the shipping modules over in-memory KeyslotAreas — add / open / rotate /
 * revoke, the encrypted duress flag, and the deniable backend's passphrase-derived placement — which
 * is behaviour (not a crypto KAT), so it self-checks with PASS lines rather than a Python diff.
 *
 * KSB_SIDECAR is the same labeled-table code path as KSB_HEADER (is_labeled()), differing only in the
 * KeyslotArea medium (a file vs the header region), so exercising KSB_HEADER covers it.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* ---- test KDF: PBKDF2-HMAC-SHA256 over the real Sha2.c (matches keyslot_poc.c) ---- */
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

/* ---- in-memory KeyslotArea ---- */
#define AREA_SLOTS 64
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }

/* deterministic "CSPRNG" for reproducible tests (NOT for production) */
static uint32_t g_rng = 0xC0FFEEu;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

#define VMK_LEN 64
static unsigned char VMK[VMK_LEN];

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-46s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

static void fill_vmk (void) { int i; for (i=0;i<VMK_LEN;i++) VMK[i]=(unsigned char)(0x40+i); }

int main (void)
{
	KeyslotArea area; area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	KeyslotStoreCfg cfg;
	unsigned char out[VMK_LEN]; int flags, idxA, idxB, idx3, idx4;

	fill_vmk();
	/* cost kept low: this harness tests the store logic + constant-time search (KDF on every slot),
	   not the KDF iteration count. The constant-time search runs cfg.cost per slot per open. */
	cfg.kdf=test_kdf; cfg.cost=256; cfg.vmkLen=VMK_LEN; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand;

	/* ===== labeled backend (KSB_HEADER; KSB_SIDECAR shares this path) ===== */
	printf("[labeled: KSB_HEADER]\n");
	memset(g_area, 0, sizeof(g_area));
	cfg.backend = KSB_HEADER;
	idxA = KeyslotAdd(&cfg,&area,(const unsigned char*)"alice-pass",10,0,VMK);
	idxB = KeyslotAdd(&cfg,&area,(const unsigned char*)"bob-pass",8,KEYSLOT_FLAG_DURESS,VMK);
	check("add slot A (>=0)", idxA>=0);
	check("add slot B (>=0, distinct)", idxB>=0 && idxB!=idxA);
	check("count == 2", KeyslotCount(&cfg,&area)==2);

	memset(out,0,sizeof(out)); flags=-1;
	check("open A recovers VMK", KeyslotOpen(&cfg,&area,(const unsigned char*)"alice-pass",10,out,&flags) && !memcmp(out,VMK,VMK_LEN));
	check("A flags == 0", flags==0);
	memset(out,0,sizeof(out)); flags=-1;
	check("open B recovers VMK", KeyslotOpen(&cfg,&area,(const unsigned char*)"bob-pass",8,out,&flags) && !memcmp(out,VMK,VMK_LEN));
	check("B flags == DURESS", flags==KEYSLOT_FLAG_DURESS);
	check("wrong passphrase rejected", !KeyslotOpen(&cfg,&area,(const unsigned char*)"mallory",7,out,&flags));

	check("revoke A ok", KeyslotRevoke(&cfg,&area,idxA)==0);
	check("count == 1 after revoke", KeyslotCount(&cfg,&area)==1);
	check("revoked A no longer opens", !KeyslotOpen(&cfg,&area,(const unsigned char*)"alice-pass",10,out,&flags));
	check("B still opens after A revoked", KeyslotOpen(&cfg,&area,(const unsigned char*)"bob-pass",8,out,&flags) && !memcmp(out,VMK,VMK_LEN));

	/* rotate: add C, verify, revoke B */
	{
		int idxC = KeyslotAdd(&cfg,&area,(const unsigned char*)"carol-new",9,0,VMK);
		check("rotate: add C ok", idxC>=0);
		check("rotate: C opens", KeyslotOpen(&cfg,&area,(const unsigned char*)"carol-new",9,out,&flags) && !memcmp(out,VMK,VMK_LEN));
		check("rotate: revoke B ok", KeyslotRevoke(&cfg,&area,idxB)==0);
		check("rotate: B gone, C remains", !KeyslotOpen(&cfg,&area,(const unsigned char*)"bob-pass",8,out,&flags)
		      && KeyslotOpen(&cfg,&area,(const unsigned char*)"carol-new",9,out,&flags));
	}

	/* ===== deniable backend (KSB_DENIABLE): bare records, passphrase-derived placement ===== */
	printf("[deniable: KSB_DENIABLE]\n");
	det_rand(g_area, sizeof(g_area));   /* fill with "random" so bare records blend in */
	cfg.backend = KSB_DENIABLE;
	idx3 = KeyslotAdd(&cfg,&area,(const unsigned char*)"deniable-3",10,0,VMK);
	idx4 = KeyslotAdd(&cfg,&area,(const unsigned char*)"deniable-4",10,KEYSLOT_FLAG_DURESS,VMK);
	check("deniable adds land in distinct slots", idx3>=0 && idx4>=0 && idx3!=idx4);
	memset(out,0,sizeof(out)); flags=-1;
	check("deniable open 3 recovers VMK", KeyslotOpen(&cfg,&area,(const unsigned char*)"deniable-3",10,out,&flags) && !memcmp(out,VMK,VMK_LEN));
	check("deniable 3 flags == 0", flags==0);
	memset(out,0,sizeof(out)); flags=-1;
	check("deniable open 4 recovers VMK + DURESS", KeyslotOpen(&cfg,&area,(const unsigned char*)"deniable-4",10,out,&flags)
	      && !memcmp(out,VMK,VMK_LEN) && flags==KEYSLOT_FLAG_DURESS);
	check("deniable wrong passphrase rejected", !KeyslotOpen(&cfg,&area,(const unsigned char*)"deniable-x",10,out,&flags));
	check("deniable not enumerable (count==0)", KeyslotCount(&cfg,&area)==0);

	printf("%s\n", all_pass ? "ALL KEYSLOT LIFECYCLE CHECKS PASSED" : "KEYSLOT LIFECYCLE CHECKS FAILED");
	return all_pass ? 0 : 1;
}
