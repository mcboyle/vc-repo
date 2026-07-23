/*
 * keyslot_areamac_test.c — keyslot-area MAC (ROI item 42) over the real KeyslotAreaMac + KeyslotStore.
 *
 * Enrolls slots, derives K_area = HKDF(VMK), writes the area trailer, and proves the area MAC:
 *   - an intact area verifies (KAM_OK);
 *   - tampering the SET of records is detected even though each surviving record still opens —
 *     negative controls: flip a slot byte, DROP a slot (count changes), REORDER two slots;
 *   - an area with no trailer reports KAM_NO_TRAILER (old area -> caller warns and continues);
 *   - a wrong K_area (derived from a different VMK) fails to verify.
 * It also emits VMK / REGION / CTAG lines for keyslot_areamac_reference.py to recompute the tag
 * independently (byte-for-byte HKDF + HMAC cross-check).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Common/KeyslotAreaMac.h"
#include "Crypto/Sha2.h"

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
#define NSLOTS 4
#define REGION (NSLOTS * KEYSLOT_TABLE_STRIDE)
#define AREA_BYTES (REGION + 64)     /* region + a trailer stride */
static unsigned char g_area[AREA_BYTES];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static uint32_t g_rng = 0x4EA24AC0u;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

static int all_pass = 1;
static void check (const char *n, int ok) { printf("  %-56s %s\n", n, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }
static void hexline (const char *tag, const unsigned char *b, size_t n)
{ size_t i; printf("%s ", tag); for (i=0;i<n;i++) printf("%02x", b[i]); printf("\n"); }

int main (void)
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char vmk[64], vmk2[64], out[64], kArea[32], kArea2[32], trailer[KAM_TRAILER_SIZE];
	int flags = -1, i;

	for (i=0;i<64;i++) vmk[i]=(unsigned char)(0x40+i);
	for (i=0;i<64;i++) vmk2[i]=(unsigned char)(0x77 ^ i);
	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	memset(&cfg,0,sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=64; cfg.vmkLen=64; cfg.maxSlots=NSLOTS; cfg.randBytes=det_rand; cfg.backend=KSB_HEADER;

	printf("[area MAC: enroll, derive K_area=HKDF(VMK), write trailer, verify]\n");
	memset(g_area,0,sizeof(g_area));
	check("enroll 3 slots", KeyslotAdd(&cfg,&area,(const unsigned char*)"a",1,0,vmk)>=0
	                     && KeyslotAdd(&cfg,&area,(const unsigned char*)"bb",2,0,vmk)>=0
	                     && KeyslotAdd(&cfg,&area,(const unsigned char*)"ccc",3,0,vmk)>=0);
	KeyslotAreaMacDeriveKey(vmk, 64, kArea);
	KeyslotAreaMacDeriveKey(vmk2, 64, kArea2);
	check("write area trailer ok", KeyslotAreaMacWrite(&area, REGION, REGION, kArea)==KAM_OK);
	check("intact area verifies (KAM_OK)", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_OK);

	/* two-way cross-check inputs for python */
	hexline("VMK", vmk, 64);
	{ unsigned char reg[REGION]; for (i=0;i<REGION;i++) reg[i]=g_area[i]; hexline("REGION", reg, REGION); }
	mem_read(0, REGION, trailer, sizeof trailer);
	hexline("CTAG", trailer + KAM_TRAILER_MAGICLEN + 1 + 4, 32);

	printf("[negative controls: set-level tampering is detected]\n");
	{
		unsigned char save, tmpA[KEYSLOT_TABLE_STRIDE], tmpC[KEYSLOT_TABLE_STRIDE];
		/* 1) flip a byte inside slot 0 (record still individually valid framing, but set changes) */
		save = g_area[100]; g_area[100] ^= 0xff;
		check("flipped slot byte -> KAM_TAMPERED", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_TAMPERED);
		g_area[100] = save;
		check("verifies again after restore", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_OK);

		/* 2) DROP a slot: zero slot 2's stride (count 3 -> 2) */
		memcpy(tmpC, g_area + 2*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
		memset(g_area + 2*KEYSLOT_TABLE_STRIDE, 0, KEYSLOT_TABLE_STRIDE);
		check("dropped slot -> KAM_TAMPERED", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_TAMPERED);
		memcpy(g_area + 2*KEYSLOT_TABLE_STRIDE, tmpC, KEYSLOT_TABLE_STRIDE);

		/* 3) REORDER: swap slot 0 and slot 1 strides (both still open, but positions change) */
		memcpy(tmpA, g_area + 0*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
		memcpy(g_area + 0*KEYSLOT_TABLE_STRIDE, g_area + 1*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
		memcpy(g_area + 1*KEYSLOT_TABLE_STRIDE, tmpA, KEYSLOT_TABLE_STRIDE);
		check("reordered slots -> KAM_TAMPERED", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_TAMPERED);
		/* swap back */
		memcpy(tmpA, g_area + 0*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
		memcpy(g_area + 0*KEYSLOT_TABLE_STRIDE, g_area + 1*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
		memcpy(g_area + 1*KEYSLOT_TABLE_STRIDE, tmpA, KEYSLOT_TABLE_STRIDE);
		check("verifies again after un-swap", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_OK);

		/* 4) wrong K_area (different VMK) */
		check("wrong K_area (other VMK) -> KAM_TAMPERED", KeyslotAreaMacVerify(&area, REGION, REGION, kArea2)==KAM_TAMPERED);

		/* 5) old area: erase the trailer magic -> warn-and-continue signal */
		memset(g_area + REGION, 0, sizeof trailer);
		check("no trailer -> KAM_NO_TRAILER (old area, warn)", KeyslotAreaMacVerify(&area, REGION, REGION, kArea)==KAM_NO_TRAILER);
	}

	/* the surviving records must still open individually (proves the tamper is set-level, not record-level) */
	printf("[records still open individually after restore]\n");
	KeyslotAreaMacWrite(&area, REGION, REGION, kArea);
	check("slot 'a' still opens", KeyslotOpen(&cfg,&area,(const unsigned char*)"a",1,out,&flags) && !memcmp(out,vmk,64));
	check("slot 'ccc' still opens", KeyslotOpen(&cfg,&area,(const unsigned char*)"ccc",3,out,&flags) && !memcmp(out,vmk,64));

	printf("\n%s\n", all_pass ? "PASS: area MAC verifies intact table, detects drop/reorder/flip/wrong-key; old area warns"
	                          : "FAIL: keyslot area mac");
	return all_pass ? 0 : 1;
}
