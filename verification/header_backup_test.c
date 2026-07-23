/*
 * header_backup_test.c — integrity-checked header/keyslot-area backup (ROI item 44) over real modules.
 *
 * Proves backup -> corrupt-the-live-area -> restore recovers the keyslots, that the integrity tag
 * DETECTS a corrupted backup, and that Restore REFUSES to write an unverified blob. Negative controls:
 * a flipped byte in the backup fails verification (HB_ERR_INTEGRITY); a bad magic / truncation is
 * rejected as HB_ERR_FORMAT; and Restore of a corrupt blob leaves the area untouched.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Common/HeaderBackup.h"
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
#define AREA_SLOTS 4
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static uint32_t g_rng = 0xBADC0DEu;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

static int all_pass = 1;
static void check (const char *n, int ok) { printf("  %-56s %s\n", n, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

int main (void)
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char vmk[64], out[64], backup[sizeof(g_area) + HEADER_BACKUP_OVERHEAD];
	size_t blen = 0; int flags = -1, i;

	for (i=0;i<64;i++) vmk[i]=(unsigned char)(0x40+i);
	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	memset(&cfg,0,sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=64; cfg.vmkLen=64; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand; cfg.backend=KSB_HEADER;

	printf("[backup / corrupt / restore]\n");
	memset(g_area,0,sizeof(g_area));
	check("enroll two slots", KeyslotAdd(&cfg,&area,(const unsigned char*)"alice",5,0,vmk)>=0
	                        && KeyslotAdd(&cfg,&area,(const unsigned char*)"bob",3,0,vmk)>=0);

	check("HeaderBackupCreate ok", HeaderBackupCreate(&area, backup, sizeof(backup), &blen)==HB_OK);
	check("backup verifies (HB_OK)", HeaderBackupVerify(backup, blen)==HB_OK);

	/* corrupt the LIVE area so a slot no longer opens */
	g_area[0] ^= 0xff; g_area[100] ^= 0xff;
	check("after corruption, alice no longer opens", !KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags));

	check("HeaderBackupRestore ok", HeaderBackupRestore(backup, blen, &area)==HB_OK);
	check("after restore, alice opens again", KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags) && !memcmp(out,vmk,64));
	check("after restore, bob opens again",   KeyslotOpen(&cfg,&area,(const unsigned char*)"bob",3,out,&flags)   && !memcmp(out,vmk,64));

	printf("[negative controls: a corrupt backup must be detected and refused]\n");
	{
		unsigned char bad[sizeof(backup)]; size_t before;
		/* 1) flip a byte inside the backed-up area -> integrity tag mismatch */
		memcpy(bad, backup, blen);
		bad[HEADER_BACKUP_OVERHEAD] ^= 0x01;   /* a byte in the area portion (after the 17-byte header) */
		check("flipped backup byte fails verification (HB_ERR_INTEGRITY)", HeaderBackupVerify(bad, blen)==HB_ERR_INTEGRITY);
		/* Restore must refuse and leave the (good) area untouched */
		before = 0; for (i=0;i<64;i++) before += g_area[i];
		check("Restore refuses the corrupt backup", HeaderBackupRestore(bad, blen, &area)==HB_ERR_INTEGRITY);
		{ size_t after=0; for (i=0;i<64;i++) after += g_area[i]; check("area left untouched by the refused restore", after==before); }
		/* 2) bad magic */
		memcpy(bad, backup, blen); bad[0] ^= 0xff;
		check("bad magic rejected (HB_ERR_FORMAT)", HeaderBackupVerify(bad, blen)==HB_ERR_FORMAT);
		/* 3) truncation */
		check("truncated blob rejected (HB_ERR_FORMAT)", HeaderBackupVerify(backup, blen-1)==HB_ERR_FORMAT);
	}

	printf("\n%s\n", all_pass ? "PASS: integrity-checked backup restores the area and detects/refuses corruption"
	                          : "FAIL: header backup");
	return all_pass ? 0 : 1;
}
