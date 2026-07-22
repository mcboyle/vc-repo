/*
 * keyslot_fuzz.c — fuzz the keyslot record parser (ROI item 31), run under ASan + UBSan.
 *
 * The parse/open path (KeyslotStore.c) is the code that touches ATTACKER-CONTROLLED bytes: a keyslot
 * table (or deniable free-space) can be arbitrary garbage, a partial remnant, or a hostile record.
 * This driver feeds thousands of malformed / random / half-structured KeyslotAreas — and randomized
 * (but in-bounds) configs — to the REAL compiled KeyslotOpen / KeyslotOpenAt / KeyslotCount /
 * KeyslotRevoke (+ the policy variants). It asserts nothing itself: ASan/UBSan are the oracle — any
 * out-of-bounds access, use of uninitialised data, integer UB, or crash fails the run. A clean pass
 * means the parser stayed in-bounds and returned safely (0 / no-match) on every malformed input.
 *
 * Deterministic: a fixed-seed xorshift RNG (no wall clock), so a failure reproduces exactly.
 *
 * VC_FUZZ_NEGCTL builds the negative control: a deliberately-buggy parser that trusts a record-supplied
 * length and indexes past the buffer. It MUST fault under ASan — proving this fuzz+sanitizer harness
 * would actually catch an out-of-bounds bug in the real parser rather than pass vacuously.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"

/* ---- test KDF (same PBKDF2-HMAC-SHA256 as keyslot_store_test.c) ---- */
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
		if (sl>128) sl=128;
		memcpy(sb,salt,sl); sb[sl]=(unsigned char)(blk>>24); sb[sl+1]=(unsigned char)(blk>>16);
		sb[sl+2]=(unsigned char)(blk>>8); sb[sl+3]=(unsigned char)blk;
		hmac256(pw,pwl,sb,sl+4,U); memcpy(T,U,DIG);
		for (j=1;j<iters;j++){ hmac256(pw,pwl,U,DIG,U); for(k=0;k<DIG;k++) T[k]^=U[k]; }
		{ int off=(blk-1)*DIG, n=(outLen-off<DIG)?(outLen-off):DIG; for(i=0;i<n;i++) out[off+i]=T[i]; }
	}
}

/* ---- deterministic xorshift RNG ---- */
static uint64_t g_s = 0x123456789abcdefULL;
static uint64_t xr (void) { uint64_t x=g_s; x^=x<<13; x^=x>>7; x^=x<<17; g_s=x; return x; }
static unsigned rr (unsigned n) { return (unsigned)(xr() % (n ? n : 1)); }

/* ---- in-memory KeyslotArea ---- */
#define AREA_SLOTS 16
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
static int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
static int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
static uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static void fuzz_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++) p[i]=(unsigned char)xr(); }

#if defined(VC_FUZZ_NEGCTL)
/* Deliberately-buggy parser: trusts a length taken from the (attacker-controlled) record and reads
   past the buffer. ASan must catch this — it stands in for a real parser OOB the fuzzer should find. */
static int buggy_parse (void)
{
	unsigned char rec[KEYSLOT_TABLE_STRIDE];
	volatile unsigned char sink = 0;
	unsigned int claimed;
	memcpy(rec, g_area, sizeof(rec));
	claimed = (unsigned)rec[12] | ((unsigned)rec[13] << 8);   /* "plen" straight from the record */
	/* index a STRIDE-sized buffer by an unbounded record field -> out of bounds for large claimed */
	sink = rec[46 + claimed + 900];
	return (int) sink;
}
#endif

int main (void)
{
	KeyslotArea area; area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	unsigned char out[KEYSLOT_VMK_MAX];
	int flags;
	long iters = 40000, it;
	const int backends[3] = { KSB_HEADER, KSB_SIDECAR, KSB_DENIABLE };
	unsigned long long sink = 0;

#if defined(VC_FUZZ_NEGCTL)
	fuzz_rand(g_area, sizeof(g_area));
	g_area[12] = 0xff; g_area[13] = 0xff;         /* claimed length ~65535 */
	printf("NEGCTL: invoking a parser that trusts a record-supplied length (ASan must fault)\n");
	fflush(stdout);
	return buggy_parse();                          /* expected: ASan abort before we return */
#else
	for (it = 0; it < iters; it++)
	{
		KeyslotStoreCfg cfg;
		int shape = rr(3);
		memset(&cfg, 0, sizeof(cfg));
		cfg.kdf = test_kdf;
		cfg.cost = 1 + rr(4);                      /* tiny cost: this fuzzes the PARSER, not the KDF */
		cfg.vmkLen = 16 + (int)rr(64);             /* 16..79 */
		cfg.maxSlots = 1 + (int)rr(AREA_SLOTS);
		cfg.randBytes = fuzz_rand;
		cfg.afStripes = (rr(2) ? 0 : 2 + (int)rr(3));
		cfg.backend = backends[rr(3)];
#if defined(VC_ENABLE_KEYSLOT_POLICY)
		cfg.policy = rr(2);
#endif

		/* shape the area: fully random, or seeded with a few "VCKS" magics + garbage fields,
		   or mostly-zero with occasional structure */
		if (shape == 0) fuzz_rand(g_area, sizeof(g_area));
		else if (shape == 1) {
			memset(g_area, 0, sizeof(g_area));
			{ unsigned k, m = rr(AREA_SLOTS);
			  for (k=0;k<=m;k++){ unsigned s = rr(AREA_SLOTS); unsigned char *r = g_area + (size_t)s*KEYSLOT_TABLE_STRIDE;
			    memcpy(r,"VCKS",4); fuzz_rand(r+4, 200 + rr(400)); } }
		} else {
			fuzz_rand(g_area, sizeof(g_area));
			{ unsigned s = rr(AREA_SLOTS); memcpy(g_area + (size_t)s*KEYSLOT_TABLE_STRIDE, "VCKS", 4); }
		}

		{
			unsigned char pass[24]; int pl = 1 + (int)rr(23);
			fuzz_rand(pass, (size_t)pl);
			flags = 0;
			sink += (unsigned)KeyslotCount(&cfg,&area);
			sink += (unsigned)KeyslotOpen(&cfg,&area,pass,pl,out,&flags);
			sink += (unsigned)KeyslotOpenAt(&cfg,&area,(int)rr(AREA_SLOTS+2)-1,pass,pl,out,&flags);
			(void)KeyslotRevoke(&cfg,&area,(int)rr(AREA_SLOTS+2)-1);
#if defined(VC_ENABLE_KEYSLOT_POLICY)
			if (cfg.policy) {
				uint64 exp = 0;
				sink += (unsigned)KeyslotOpenPolicy(&cfg,&area,pass,pl,rr(2)?0:1000,out,&flags,&exp);
				sink += (unsigned)KeyslotOpenAtPolicy(&cfg,&area,(int)rr(AREA_SLOTS+2)-1,pass,pl,0,out,&flags,0,0);
			}
#endif
		}
	}
	printf("keyslot parser fuzz: %ld iterations, no ASan/UBSan fault (sink=%llu)\n", iters, sink & 0xffff);
	return 0;
#endif
}
