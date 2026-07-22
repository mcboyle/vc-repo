/*
 * keyslot_policy_test.c — per-slot policy (ROI item 15) over the REAL KeyslotStore.c.
 *
 * Two ways, per the project convention:
 *   layer 2 (this file): drive the real compiled KeyslotAddPolicy / KeyslotOpenPolicy /
 *     KeyslotOpenAtPolicy over an in-memory KeyslotArea and check read-only, expiry, and max-attempts
 *     behaviour, each with a NEGATIVE CONTROL that fails if the behaviour is absent;
 *   layer 1 (keyslot_policy_reference.py): independently computes the v2 payload layout
 *     (flags[1] || expiryUnix[8] BE || vmk) for a fixed slot, diffed byte-for-byte against the "REF"
 *     lines this program prints after a real wrap+unwrap round-trip.
 *
 * The wrapping crypto itself is already proven in keyslot_poc.c (step 8) / keyslot_store_test.c
 * (step 9); this exercises only the new policy semantics.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* ---- test KDF: PBKDF2-HMAC-SHA256 over real Sha2.c (identical to keyslot_store_test.c) ---- */
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
static uint32_t g_rng = 0xC0FFEEu;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

#define VMK_LEN 64
static unsigned char VMK[VMK_LEN];
static void fill_vmk (void) { int i; for (i=0;i<VMK_LEN;i++) VMK[i]=(unsigned char)(0x40+i); }

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-52s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }
static void print_hex (const char *label, const unsigned char *p, int n){ int i; printf("%s",label); for(i=0;i<n;i++) printf("%02x",p[i]); printf("\n"); }

/* fixed inputs for the layer-1 python cross-check */
#define REF_FLAGS   KEYSLOT_FLAG_READONLY            /* 0x02 */
static const uint64 REF_EXPIRY = UINT64_C(0x0000000064abcdef);

int main (void)
{
	KeyslotArea area; area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	KeyslotStoreCfg cfg;
	unsigned char out[VMK_LEN]; int flags; uint64 expiry;

	fill_vmk();
	memset(&cfg, 0, sizeof(cfg));
	cfg.kdf=test_kdf; cfg.cost=256; cfg.vmkLen=VMK_LEN; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand;
	cfg.backend = KSB_HEADER;
	cfg.policy  = 1;                              /* v2 policy records */

	/* ============================ read-only ============================ */
	printf("[read-only]\n");
	memset(g_area, 0, sizeof(g_area));
	{
		int ro = KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"ro-pass",7, KEYSLOT_FLAG_READONLY, VMK, 0, 0);
		int rw = KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"rw-pass",7, 0,                     VMK, 0, 0);
		check("add read-only slot", ro>=0);
		check("add read-write slot", rw>=0 && rw!=ro);
		flags=-1; memset(out,0,sizeof(out));
		check("read-only slot opens + recovers VMK", KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"ro-pass",7,0,out,&flags,&expiry) && !memcmp(out,VMK,VMK_LEN));
		check("read-only bit set", (flags & KEYSLOT_FLAG_READONLY)!=0);
		flags=-1;
		check("read-write slot opens", KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"rw-pass",7,0,out,&flags,&expiry));
		check("NEG-CONTROL: read-write slot does NOT carry the read-only bit", (flags & KEYSLOT_FLAG_READONLY)==0);
	}

	/* ============================ expiry ============================ */
	printf("[expiry]\n");
	memset(g_area, 0, sizeof(g_area));
	{
		uint64 T = UINT64_C(1000000000);
		check("add expiring slot (expiry=T)",  KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"exp-pass",8,0,VMK,T,0)>=0);
		check("add never-expiring slot (expiry=0)", KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"forever",7,0,VMK,0,0)>=0);
		flags=-1;
		check("opens BEFORE expiry (now<T)",   KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"exp-pass",8,T-1,out,&flags,&expiry)==1);
		check("expiry value round-trips",      expiry==T);
		check("FAILS AFTER expiry (now>T), silently", KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"exp-pass",8,T+1,out,&flags,&expiry)==0);
		check("opens with expiry check disabled (now=0)", KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"exp-pass",8,0,out,&flags,&expiry)==1);
		check("NEG-CONTROL: never-expiring slot opens far in the future", KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"forever",7,UINT64_C(9999999999),out,&flags,&expiry)==1);
	}

	/* ============================ max-attempts (admin path) ============================ */
	printf("[max-attempts]\n");
	memset(g_area, 0, sizeof(g_area));
	{
		int idx, a, mx, r1,r2,r3,r4;
		idx = KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"lock-pass",9,0,VMK,0,3);   /* maxAttempts=3 */
		check("add attempt-limited slot (max=3)", idx>=0);
		r1 = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"wrong1",6,0,out,&flags,&a,&mx);
		check("wrong #1 rejected, attempts=1", r1==0 && a==1 && mx==3);
		r2 = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"wrong2",6,0,out,&flags,&a,&mx);
		check("wrong #2 rejected, attempts=2", r2==0 && a==2);
		r3 = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"wrong3",6,0,out,&flags,&a,&mx);
		check("wrong #3 rejected, attempts=3", r3==0 && a==3);
		r4 = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"lock-pass",9,0,out,&flags,&a,&mx);
		check("locked out: correct pass now refused (KEYSLOT_LOCKED)", r4==KEYSLOT_LOCKED);

		/* NEG-CONTROL: a fresh limited slot resets its counter on a correct open before lockout */
		memset(g_area, 0, sizeof(g_area));
		idx = KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"reset-pass",10,0,VMK,0,3);
		KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"nope",4,0,out,&flags,&a,&mx);
		KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"nope",4,0,out,&flags,&a,&mx);
		check("NEG-CONTROL: 2 wrong -> attempts=2 (not yet locked)", a==2);
		r1 = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"reset-pass",10,0,out,&flags,&a,&mx);
		check("NEG-CONTROL: correct pass opens and resets counter to 0", r1==1 && a==0 && !memcmp(out,VMK,VMK_LEN));
	}

	/* ============================ rollback limitation (honest demo) ============================ */
	printf("[rollback limitation]\n");
	memset(g_area, 0, sizeof(g_area));
	{
		int idx, a, mx, r;
		unsigned char snapshot[KEYSLOT_TABLE_STRIDE];
		idx = KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"rb-pass",7,0,VMK,0,2);   /* max=2 */
		memcpy(snapshot, g_area + (uint64)idx*KEYSLOT_TABLE_STRIDE, KEYSLOT_TABLE_STRIDE); /* pre-attempt copy */
		KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"x",1,0,out,&flags,&a,&mx);
		KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"x",1,0,out,&flags,&a,&mx);
		r = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"rb-pass",7,0,out,&flags,&a,&mx);
		check("locked after 2 wrong (max=2)", r==KEYSLOT_LOCKED);
		/* an imaging attacker restores the pre-attempt slot bytes... */
		memcpy(g_area + (uint64)idx*KEYSLOT_TABLE_STRIDE, snapshot, KEYSLOT_TABLE_STRIDE);
		r = KeyslotOpenAtPolicy(&cfg,&area,idx,(const unsigned char*)"rb-pass",7,0,out,&flags,&a,&mx);
		check("DOCUMENTED LIMITATION: restoring old bytes resets the counter -> opens again", r==1 && a==0);
		printf("  (max-attempts is rollback-defeatable without a TPM/secure-element counter; see docs/KEYSLOT-POLICY-DESIGN.md)\n");
	}

	/* ============================ v1 legacy still opens (byte-compat) ============================ */
	printf("[v1 legacy compat]\n");
	memset(g_area, 0, sizeof(g_area));
	{
		KeyslotStoreCfg v1 = cfg; v1.policy = 0;
		int idx = KeyslotAdd(&v1,&area,(const unsigned char*)"legacy",6,KEYSLOT_FLAG_DURESS,VMK);
		flags=-1;
		check("v1 add ok", idx>=0);
		check("v1 opens via legacy KeyslotOpen + flags round-trip",
		      KeyslotOpen(&v1,&area,(const unsigned char*)"legacy",6,out,&flags) && !memcmp(out,VMK,VMK_LEN) && flags==KEYSLOT_FLAG_DURESS);
	}

	/* ============================ layer-1 REF lines (v2 payload layout) ============================ */
	printf("[payload layout REF — diffed against keyslot_policy_reference.py]\n");
	memset(g_area, 0, sizeof(g_area));
	{
		unsigned char eb[8];
		int idx = KeyslotAddPolicy(&cfg,&area,(const unsigned char*)"ref-pass",8, REF_FLAGS, VMK, REF_EXPIRY, 0);
		flags=-1; memset(out,0,sizeof(out));
		(void) idx;
		KeyslotOpenPolicy(&cfg,&area,(const unsigned char*)"ref-pass",8,0,out,&flags,&expiry);
		eb[0]=(unsigned char)(expiry>>56); eb[1]=(unsigned char)(expiry>>48); eb[2]=(unsigned char)(expiry>>40); eb[3]=(unsigned char)(expiry>>32);
		eb[4]=(unsigned char)(expiry>>24); eb[5]=(unsigned char)(expiry>>16); eb[6]=(unsigned char)(expiry>>8); eb[7]=(unsigned char)expiry;
		printf("REF flags=%02x\n", flags & 0xff);
		print_hex("REF expiry=", eb, 8);
		print_hex("REF vmk=", out, VMK_LEN);
	}

	printf("\n%s\n", all_pass ? "PASS: per-slot policy (read-only, expiry, max-attempts) behaves + negative controls hold"
	                          : "FAIL: keyslot policy");
	return all_pass ? 0 : 1;
}
