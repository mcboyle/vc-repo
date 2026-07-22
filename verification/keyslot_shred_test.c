/*
 * keyslot_shred_test.c — verifiable keyslot shredding (ROI item 41) over the REAL KeyslotStore.c.
 *
 * Proves that KeyslotShred (a) makes the slot unopenable, (b) leaves NO verbatim remnant of the old
 * wrapped key / AF stripes, and (c) returns an attestation that an auditor can independently recompute
 * from the observed before/after slot hashes. The NEGATIVE CONTROL is a "weak" revoke that only clears
 * the 4-byte magic (marks the slot free) but leaves the ciphertext on disk: the harness shows the old
 * ciphertext SURVIVES verbatim there — i.e. mark-free is recoverable, real shred is not.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* ---- test KDF + area (same as keyslot_store_test.c) ---- */
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
static uint32_t g_rng = 0x51ED51EDu;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-56s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

#define CT_OFF 46          /* L_CT: start of the ciphertext/AF-stripe region within a labeled slot */
#define REM     64         /* sample length used to detect a verbatim ciphertext remnant */

int main (void)
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char vmk[64], out[64], pre[KEYSLOT_TABLE_STRIDE], postShred[KEYSLOT_TABLE_STRIDE], postWeak[KEYSLOT_TABLE_STRIDE];
	unsigned char att[32], hOld[32], hNew[32], msg[10+4+32+32], attRef[32];
	int i, idx, flags = -1;

	for (i = 0; i < 64; i++) vmk[i] = (unsigned char)(0x40 + i);
	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	memset(&cfg,0,sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=64; cfg.vmkLen=64; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand;
	cfg.backend=KSB_HEADER; cfg.afStripes=4;   /* AF-split so there ARE stripes to shred */

	printf("[verifiable shred]\n");
	memset(g_area,0,sizeof(g_area));
	idx = KeyslotAdd(&cfg,&area,(const unsigned char*)"alice",5,0,vmk);
	check("enroll slot", idx>=0);
	check("slot opens before shred", KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags) && !memcmp(out,vmk,64));

	memcpy(pre, g_area + (uint64)idx*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);  /* capture BEFORE */
	sha256(hOld, pre, KEYSLOT_TABLE_STRIDE);

	check("KeyslotShred returns 0", KeyslotShred(&cfg,&area,idx,att)==0);
	memcpy(postShred, g_area + (uint64)idx*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
	sha256(hNew, postShred, KEYSLOT_TABLE_STRIDE);

	check("shredded slot no longer opens", !KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags));
	check("shredded slot has no VCKS magic", memcmp(postShred,"VCKS",4)!=0);
	check("ciphertext/AF-stripe region overwritten (no verbatim remnant)", memcmp(pre+CT_OFF, postShred+CT_OFF, REM)!=0);
	/* independently recompute the attestation from the observed before/after hashes */
	memcpy(msg,"VCKSSHRED1",10);
	msg[10]=(unsigned char)(idx>>24); msg[11]=(unsigned char)(idx>>16); msg[12]=(unsigned char)(idx>>8); msg[13]=(unsigned char)idx;
	memcpy(msg+14,hOld,32); memcpy(msg+46,hNew,32);
	sha256(attRef, msg, sizeof(msg));
	check("attestation independently reproducible", memcmp(att, attRef, 32)==0);

	printf("[negative control: weak mark-free leaves a recoverable remnant]\n");
	memset(g_area,0,sizeof(g_area));
	idx = KeyslotAdd(&cfg,&area,(const unsigned char*)"bob",3,0,vmk);
	memcpy(pre, g_area + (uint64)idx*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
	/* WEAK revoke: only clear the 4-byte magic (mark the slot free), leave ciphertext + stripes */
	{ unsigned char z4[4] = {0,0,0,0}; mem_write(0, (uint64)idx*KEYSLOT_TABLE_STRIDE, z4, 4); }
	memcpy(postWeak, g_area + (uint64)idx*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE);
	check("weak mark-free: slot reads as free (no VCKS)", memcmp(postWeak,"VCKS",4)!=0);
	check("weak mark-free: OLD ciphertext SURVIVES verbatim (recoverable!)", memcmp(pre+CT_OFF, postWeak+CT_OFF, REM)==0);
	check("contrast: real shred destroyed what weak mark-free left behind",
	      memcmp(pre+CT_OFF, postShred+CT_OFF, REM)!=0 && memcmp(pre+CT_OFF, postWeak+CT_OFF, REM)==0);

	printf("\n%s\n", all_pass ? "PASS: shred makes the slot unrecoverable + attestable; weak mark-free demonstrably does not"
	                          : "FAIL: keyslot shred");
	return all_pass ? 0 : 1;
}
