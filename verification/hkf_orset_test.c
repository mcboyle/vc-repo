/*
 * hkf_orset_test.c — multi-token OR-set (ROI item 45) over the REAL HkfOrSet + Keyslot +
 * HardwareKeyFactor objects.
 *
 * Proves the OR-set property: N independent tokens are each enrolled as their own keyslot
 * wrapping ONE master key (VMK); presenting ANY single enrolled token recovers the VMK exactly.
 * Tokens are RAW_SECRET factors with salt-binding (each returns HMAC-SHA256(secret, salt) — a
 * real per-volume challenge-response), computed via the real HKFComputeResponse.
 *
 * Negative controls (prove the property is load-bearing, not vacuous):
 *   - a token that was never enrolled opens NOTHING (HkfOrSetOpenConfig -> 0);
 *   - after revoking one token's slot, THAT token no longer opens, but every other token still
 *     does — so the OR-set is genuinely per-token, not all-or-nothing.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Common/HardwareKeyFactor.h"
#include "Common/HkfOrSet.h"
#include "Crypto/Sha2.h"

/* ---- test KDF + area (same helpers as keyslot_store_test.c / header_backup_test.c) ---- */
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
#define NTOK 4
#define AREA_SLOTS 8
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static uint32_t g_rng = 0x51A17E57u;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

static int all_pass = 1;
static void check (const char *n, int ok) { printf("  %-58s %s\n", n, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

/* Build a RAW_SECRET, salt-bound token config with a distinct secret. */
static void make_token (HKFConfig *c, unsigned char seed)
{
	int i;
	memset(c, 0, sizeof *c);
	c->backend = HKF_BACKEND_RAW_SECRET;
	c->rawSecretLen = 32;
	for (i=0;i<32;i++) c->rawSecret[i] = (unsigned char)(seed + i*7u);
	c->rawSecretBindSalt = 1;   /* HMAC-SHA256(secret, salt): a real per-volume response */
}

int main (void)
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	HKFConfig tok[NTOK], intruder;
	unsigned char vmk[64], out[64], salt[64];
	int flags = -1, i, idx[NTOK];

	for (i=0;i<64;i++) vmk[i]=(unsigned char)(0x40+i);
	for (i=0;i<64;i++) salt[i]=(unsigned char)(0xA0 ^ i);       /* the volume's PBKDF2 salt = challenge */
	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	memset(&cfg,0,sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=64; cfg.vmkLen=64; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand; cfg.backend=KSB_HEADER;
	for (i=0;i<NTOK;i++) make_token(&tok[i], (unsigned char)(0x10 + i*0x20));
	make_token(&intruder, 0xF3);                                 /* a token that is never enrolled */

	printf("[OR-set: enroll %d tokens, any one opens] (config API, RAW_SECRET salt-bound)\n", NTOK);
	memset(g_area,0,sizeof(g_area));
	check("HkfOrSetEnrollConfigs enrolls all tokens",
	      HkfOrSetEnrollConfigs(&cfg,&area,tok,NTOK,salt,sizeof salt,vmk)==NTOK);
	check("area now reports NTOK slots", KeyslotCount(&cfg,&area)==NTOK);

	for (i=0;i<NTOK;i++) {
		char nm[64]; int ok;
		memset(out,0,sizeof out); flags=-1;
		ok = HkfOrSetOpenConfig(&cfg,&area,&tok[i],salt,sizeof salt,out,&flags)==1 && !memcmp(out,vmk,64);
		snprintf(nm,sizeof nm,"token %d alone recovers the exact VMK", i);
		check(nm, ok);
	}

	printf("[negative control: a non-enrolled token opens nothing]\n");
	memset(out,0,sizeof out);
	check("intruder token opens no slot (returns 0)",
	      HkfOrSetOpenConfig(&cfg,&area,&intruder,salt,sizeof salt,out,&flags)==0);
	check("intruder left VMK buffer untouched (all zero)", out[0]==0 && out[63]==0);

	printf("[revoke one token -> only that token stops working] (response API)\n");
	/* Re-enroll from scratch capturing indices, so we can revoke a specific token's slot. */
	memset(g_area,0,sizeof(g_area)); g_rng=0x51A17E57u;
	{
		unsigned char resp[NTOK][HKF_MAX_RESPONSE]; int rlen[NTOK], rc;
		for (i=0;i<NTOK;i++) {
			rc = HKFComputeResponse(&tok[i], salt, sizeof salt, resp[i], &rlen[i]);
			idx[i] = KeyslotAdd(&cfg,&area,resp[i],rlen[i],0,vmk);
			if (rc!=HKF_OK || idx[i]<0) { check("setup: compute+enroll each response", 0); }
		}
		check("setup: all responses computed + enrolled", 1);
		/* revoke token 1's slot */
		check("KeyslotRevoke(token 1) ok", KeyslotRevoke(&cfg,&area,idx[1])==0);

		for (i=0;i<NTOK;i++) {
			char nm[80]; int opened;
			memset(out,0,sizeof out);
			opened = HkfOrSetOpen(&cfg,&area,resp[i],rlen[i],out,&flags)==1 && !memcmp(out,vmk,64);
			if (i==1) { snprintf(nm,sizeof nm,"revoked token 1 no longer opens"); check(nm, !opened); }
			else      { snprintf(nm,sizeof nm,"token %d still opens after token 1 revoked", i); check(nm, opened); }
		}
		memset(resp,0,sizeof resp);
	}

	printf("\n%s\n", all_pass ? "PASS: OR-set — any one enrolled token unlocks; non-enrolled fails; revoke is per-token"
	                          : "FAIL: hkf or-set");
	return all_pass ? 0 : 1;
}
