/*
 * keyslot_verify_test.c — offline "verify" without mounting (ROI item 16) over the real
 * KeyslotStore.KeyslotStructuralCheck.
 *
 * Proves the offline verifier accepts a clean keyslot area and FLAGS framing corruption
 * (version / cost / payload-length) WITHOUT the passphrase. Negative controls corrupt each framing
 * field and require detection. It also documents the honest boundary: a flipped CIPHERTEXT byte is
 * NOT visible to the structural check (that needs the passphrase or the item-42 area MAC), but the
 * mount path (KeyslotOpen) still rejects it via the per-record AEAD tag.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* labeled record offsets (mirror KeyslotStore.c) */
#define L_VER 4
#define L_COST 8
#define L_PLEN 12
#define L_CT  46

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
#define AREA_SLOTS 6
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static uint32_t g_rng = 0x1CE1CE1Cu;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

static int all_pass = 1;
static void check (const char *n, int ok) { printf("  %-58s %s\n", n, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

int main (void)
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char vmk[64], out[64];
	int wf = -1, mf = -1, i, flags = -1;

	for (i=0;i<64;i++) vmk[i]=(unsigned char)(0x40+i);
	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	memset(&cfg,0,sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=64; cfg.vmkLen=64; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand; cfg.backend=KSB_HEADER;

	printf("[offline verify: clean area]\n");
	memset(g_area,0,sizeof(g_area));
	check("empty area verifies (0 slots, well-formed)", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==0 && wf==0 && mf==0);
	check("enroll 3 slots", KeyslotAdd(&cfg,&area,(const unsigned char*)"a",1,0,vmk)>=0
	                     && KeyslotAdd(&cfg,&area,(const unsigned char*)"bb",2,0,vmk)>=0
	                     && KeyslotAdd(&cfg,&area,(const unsigned char*)"ccc",3,0,vmk)>=0);
	check("clean area verifies (3 well-formed, 0 malformed)", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==0 && wf==3 && mf==0);

	printf("[negative controls: framing corruption must be flagged]\n");
	{
		unsigned char save;
		/* corrupt slot 0 version */
		save = g_area[0*KEYSLOT_TABLE_STRIDE + L_VER]; g_area[0*KEYSLOT_TABLE_STRIDE + L_VER] = 0x7f;
		check("bad version flagged (-1, one malformed)", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==-1 && mf==1 && wf==2);
		g_area[0*KEYSLOT_TABLE_STRIDE + L_VER] = save;
		/* corrupt slot 1 cost */
		save = g_area[1*KEYSLOT_TABLE_STRIDE + L_COST]; g_area[1*KEYSLOT_TABLE_STRIDE + L_COST] ^= 0xff;
		check("bad cost flagged", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==-1 && mf==1);
		g_area[1*KEYSLOT_TABLE_STRIDE + L_COST] = save;
		/* corrupt slot 2 payload length */
		save = g_area[2*KEYSLOT_TABLE_STRIDE + L_PLEN]; g_area[2*KEYSLOT_TABLE_STRIDE + L_PLEN] ^= 0xff;
		check("bad payload-length flagged", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==-1 && mf==1);
		g_area[2*KEYSLOT_TABLE_STRIDE + L_PLEN] = save;
		check("area verifies clean again after restore", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==0 && wf==3 && mf==0);
	}

	printf("[honest boundary: ciphertext tamper is invisible offline but caught at mount]\n");
	{
		/* flip a byte inside slot 2's ciphertext (past the framing) */
		size_t ctpos = 2*KEYSLOT_TABLE_STRIDE + L_CT + 5;
		g_area[ctpos] ^= 0x01;
		check("structural check still passes (cannot see ct tamper)", KeyslotStructuralCheck(&cfg,&area,&wf,&mf)==0);
		check("but mount (KeyslotOpen) rejects the tampered slot", !KeyslotOpen(&cfg,&area,(const unsigned char*)"ccc",3,out,&flags));
		g_area[ctpos] ^= 0x01;   /* restore */
		check("after restore, that slot opens again", KeyslotOpen(&cfg,&area,(const unsigned char*)"ccc",3,out,&flags) && !memcmp(out,vmk,64));
	}

	printf("\n%s\n", all_pass ? "PASS: offline verify accepts clean area, flags framing corruption; ct-tamper boundary documented"
	                          : "FAIL: keyslot verify");
	return all_pass ? 0 : 1;
}
