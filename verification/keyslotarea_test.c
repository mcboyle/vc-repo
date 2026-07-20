/*
 * keyslotarea_test.c — KeyslotArea volume-I/O bindings end-to-end (build_and_verify.sh step [37];
 * docs/KEYSLOTS-SPEC.md §9). Drives the REAL KeyslotAreaFile.c + KeyslotStore.c + Keyslot.c +
 * AfSplit.c over synthetic container files:
 *
 *   KSB_HEADER   — records land only in the primary header's reserved slack [512, 64K): the real
 *                  512-byte header, the hidden-header region and the data region are byte-untouched,
 *                  and slots survive a close + cold reopen (real file round-trip).
 *   KSB_SIDECAR  — whole-file table in a separate file.
 *   KSB_DENIABLE — a data-region free extent clamped below a simulated hidden-volume start; a
 *                  before/after snapshot diff is confined to exactly one stride slot, that slot has
 *                  no plaintext markers and passes frequency screens (blends into random fill), and
 *                  — stated honestly, per docs/THREAT-MODEL.md — the diff DOES reveal that a slot
 *                  changed: multi-snapshot location leakage is the documented limitation.
 *
 * Behavioural I/O test (the record crypto is proven in [8]/[36]), so PASS/FAIL lines like step [9].
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "Common/AfSplit.h"
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Common/KeyslotAreaFile.h"
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

static uint32_t g_rng = 0xA5EA5EEDu;
static void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

/* ---- synthetic container geometry (mirrors Volumes.h: header group 128K, then data) ---- */
#define HDR_EFF     512
#define HDR_SIZE    65536
#define HDR_GROUP   (2 * HDR_SIZE)
#define VOL_SIZE    262144                       /* 128K header group + 128K data */
#define FREE_START  ((uint64) HDR_GROUP)         /* data-region free extent for KSB_DENIABLE */
#define FREE_END    ((uint64) VOL_SIZE)
#define HIDDEN_AT   ((uint64) 200704)            /* simulated hidden-volume reserved start */

#define VMK_LEN 64
static unsigned char VMK[VMK_LEN];

static int all_pass = 1;
static void check (const char *name, int ok) { printf("  %-52s %s\n", name, ok?"PASS":"FAIL"); if(!ok) all_pass=0; }

static int write_file (const char *path, const unsigned char *p, size_t n)
{
	FILE *f = fopen (path, "wb");
	if (!f) return -1;
	if (fwrite (p, 1, n, f) != n) { fclose (f); return -1; }
	return fclose (f) == 0 ? 0 : -1;
}
static int read_file (const char *path, unsigned char *p, size_t n)
{
	FILE *f = fopen (path, "rb");
	if (!f) return -1;
	if (fread (p, 1, n, f) != n) { fclose (f); return -1; }
	fclose (f); return 0;
}

int main (void)
{
	static unsigned char vol[VOL_SIZE], snapA[VOL_SIZE], snapB[VOL_SIZE];
	const char *volPath = "/tmp/ksarea_vol.bin", *sidePath = "/tmp/ksarea_side.bin";
	KeyslotAreaFile ctx; KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char out[VMK_LEN]; int flags, i, idxA, idxB;

	for (i=0;i<VMK_LEN;i++) VMK[i]=(unsigned char)(0x40+i);
	memset(&cfg, 0, sizeof(cfg));
	cfg.kdf=test_kdf; cfg.cost=256; cfg.vmkLen=VMK_LEN; cfg.maxSlots=0; cfg.randBytes=det_rand;

	/* a "formatted volume": every byte random, as the format leaves header slack + free space */
	det_rand (vol, sizeof (vol));
	memcpy (snapA, vol, sizeof (vol));                       /* pristine copy for untouched checks */
	if (write_file (volPath, vol, sizeof (vol)) != 0) { printf("cannot write %s\n", volPath); return 1; }

	/* ===== KSB_HEADER: primary header slack ===== */
	printf("[KSB_HEADER: header-slack window]\n");
	check("open container", KeyslotAreaFileOpen(&ctx, volPath, 1)==0);
	KeyslotAreaBindHeaderSlack(&area, &ctx);
	check("slack window = 63 slots", area.size(area.ctx)/KEYSLOT_TABLE_STRIDE == 63);
	cfg.backend = KSB_HEADER;
	/* the slack is random fill, not zeroes: labeled_first_free needs a free slot to not look like
	   a record; random fill starting with "VCKS" has probability 2^-32 per slot — none here */
	idxA = KeyslotAdd(&cfg,&area,(const unsigned char*)"alice",5,0,VMK);
	idxB = KeyslotAdd(&cfg,&area,(const unsigned char*)"bob",3,KEYSLOT_FLAG_DURESS,VMK);
	check("add A and B through file I/O", idxA>=0 && idxB>=0 && idxA!=idxB);
	check("count == 2", KeyslotCount(&cfg,&area)==2);
	KeyslotAreaFileClose(&ctx);

	/* cold reopen: everything must come back from the medium */
	check("cold reopen", KeyslotAreaFileOpen(&ctx, volPath, 1)==0);
	KeyslotAreaBindHeaderSlack(&area, &ctx);
	memset(out,0,sizeof(out)); flags=-1;
	check("A opens after reopen", KeyslotOpen(&cfg,&area,(const unsigned char*)"alice",5,out,&flags) && !memcmp(out,VMK,VMK_LEN) && flags==0);
	check("B opens after reopen (duress intact)", KeyslotOpen(&cfg,&area,(const unsigned char*)"bob",3,out,&flags) && flags==KEYSLOT_FLAG_DURESS);
	check("wrong passphrase rejected", !KeyslotOpen(&cfg,&area,(const unsigned char*)"mallory",7,out,&flags));

	/* AF composition through the file binding */
	{
		KeyslotStoreCfg af = cfg; af.afStripes = 4;
		int idxC = KeyslotAdd(&af,&area,(const unsigned char*)"carol",5,0,VMK);
		check("AF (s=4) slot adds over file I/O", idxC>=0);
		check("AF slot opens over file I/O", KeyslotOpen(&af,&area,(const unsigned char*)"carol",5,out,&flags) && !memcmp(out,VMK,VMK_LEN));
	}
	KeyslotAreaFileClose(&ctx);

	/* geometry safety: only the slack window changed */
	if (read_file (volPath, vol, sizeof (vol)) != 0) { printf("cannot re-read\n"); return 1; }
	check("real 512-byte header untouched", memcmp(vol, snapA, HDR_EFF)==0);
	check("hidden-header region untouched", memcmp(vol+HDR_SIZE, snapA+HDR_SIZE, HDR_SIZE)==0);
	check("data region untouched", memcmp(vol+HDR_GROUP, snapA+HDR_GROUP, VOL_SIZE-HDR_GROUP)==0);

	/* ===== KSB_SIDECAR: whole file ===== */
	printf("[KSB_SIDECAR: whole-file table]\n");
	{
		static unsigned char side[16 * KEYSLOT_TABLE_STRIDE];
		memset (side, 0, sizeof (side));
		if (write_file (sidePath, side, sizeof (side)) != 0) { printf("cannot write %s\n", sidePath); return 1; }
		check("open sidecar", KeyslotAreaFileOpen(&ctx, sidePath, 1)==0);
		check("bind sidecar (16 slots)", KeyslotAreaBindSidecar(&area, &ctx)==0
		      && area.size(area.ctx)/KEYSLOT_TABLE_STRIDE == 16);
		cfg.backend = KSB_SIDECAR;
		check("sidecar add", KeyslotAdd(&cfg,&area,(const unsigned char*)"side-pass",9,0,VMK)>=0);
		check("sidecar opens", KeyslotOpen(&cfg,&area,(const unsigned char*)"side-pass",9,out,&flags) && !memcmp(out,VMK,VMK_LEN));
		KeyslotAreaFileClose(&ctx);
	}

	/* ===== KSB_DENIABLE: free-space extent, hidden-volume guard, snapshot diff ===== */
	printf("[KSB_DENIABLE: free-space window + snapshot diff]\n");
	check("guard: empty window rejected", KeyslotAreaBindDeniable(&area,&ctx,FREE_START,FREE_END,FREE_START)==-1);
	check("open container (deniable)", KeyslotAreaFileOpen(&ctx, volPath, 1)==0);
	check("bind free extent below hidden start", KeyslotAreaBindDeniable(&area,&ctx,FREE_START,FREE_END,HIDDEN_AT)==0
	      && area.size(area.ctx) == HIDDEN_AT-FREE_START);
	if (read_file (volPath, snapA, sizeof (snapA)) != 0) { printf("cannot snapshot\n"); return 1; }
	cfg.backend = KSB_DENIABLE;
	i = KeyslotAdd(&cfg,&area,(const unsigned char*)"deny-pass",9,KEYSLOT_FLAG_DURESS,VMK);
	check("deniable add lands", i>=0);
	check("deniable opens", KeyslotOpen(&cfg,&area,(const unsigned char*)"deny-pass",9,out,&flags)
	      && !memcmp(out,VMK,VMK_LEN) && flags==KEYSLOT_FLAG_DURESS);
	KeyslotAreaFileClose(&ctx);
	if (read_file (volPath, snapB, sizeof (snapB)) != 0) { printf("cannot snapshot\n"); return 1; }

	{
		/* diff must be confined to exactly the one stride slot, inside the bound window */
		uint64 lo = 0, hi = 0, expectOff = FREE_START + (uint64) i * KEYSLOT_TABLE_STRIDE;
		long   ndiff = 0; uint64 j;
		for (j = 0; j < VOL_SIZE; j++)
			if (snapA[j] != snapB[j]) { if (!ndiff) lo = j; hi = j; ndiff++; }
		check("snapshot diff nonzero (multi-snapshot leak, documented)", ndiff > 0);
		check("diff confined to one stride slot", ndiff > 0
		      && lo >= expectOff && hi < expectOff + KEYSLOT_TABLE_STRIDE);
		check("diff inside the bound window only", lo >= FREE_START && hi < HIDDEN_AT);

		/* the rewritten slot must blend into random fill: no plaintext markers, sane frequencies */
		{
			const unsigned char *slot = snapB + expectOff;
			long ones = 0, chi_num = 0; int hist[256], b, marker = 0;
			double chi = 0.0;
			memset (hist, 0, sizeof (hist));
			for (b = 0; b < KEYSLOT_TABLE_STRIDE; b++)
			{
				unsigned char v = slot[b]; int k;
				hist[v]++;
				for (k = 0; k < 8; k++) ones += (v >> k) & 1;
				if (b + 4 <= KEYSLOT_TABLE_STRIDE && memcmp (slot + b, "VCKS", 4) == 0) marker = 1;
			}
			for (b = 0; b < 256; b++)
			{
				double e = KEYSLOT_TABLE_STRIDE / 256.0;          /* 4 expected per bin */
				chi += (hist[b] - e) * (hist[b] - e) / e;
			}
			(void) chi_num;
			check("no plaintext marker in bare slot", !marker);
			/* monobit: 8192 bits, mean 4096, sd 45.25; |dev| < 4 sd */
			check("bare slot monobit within 4 sd", labs (ones - 4096L) < 181);
			/* chi-square df=255: mean 255, sd ~22.6; generous 255 + 6 sd bound */
			check("bare slot byte-histogram chi^2 sane", chi < 391.0);
		}
	}

	remove (volPath); remove (sidePath);
	printf("%s\n", all_pass ? "ALL KEYSLOT AREA CHECKS PASSED" : "KEYSLOT AREA CHECKS FAILED");
	return all_pass ? 0 : 1;
}
