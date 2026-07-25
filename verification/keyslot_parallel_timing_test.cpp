/*
 * keyslot_parallel_timing_test.cpp — the constant-time + exception-safety gate for the parallel keyslot
 * auto-search. Drives the ACTUAL product executor (src/Volume/KeyslotParallelExecutor.h
 * VolumeKeyslotParallelFor), not a replica, and the real Common/KeyslotStore.c KeyslotOpenParallel.
 *
 * Two things dudect ([46]) cannot cover:
 *   (A) CONSTANT-TIME SCAN: wall-clock depends only on the slot COUNT + the machine, never on WHICH slot
 *       matched. Isolated from kernel dm-crypt / mount noise (direct in-memory area); KDF cost tuned so
 *       per-slot work dominates thread-spawn. Asserts byte-identical VMK at slot 0 AND the last slot (an
 *       i*ct indexing regression is invisible at slot 0) and a match@0-vs-match@last delta within noise.
 *   (B) EXCEPTION-SAFETY / EAGAIN RECOVERY: std::thread creation can fail (RLIMIT_NPROC / cgroup pids.max
 *       / OOM). The executor must still run EVERY body (falling back to inline), never propagate across
 *       the C boundary, never leave a slot unrun (-> false "wrong password"). Compiled with
 *       -DVC_KS_PAR_TEST_HOOK, the g_vcKsParMaxSpawn hook forces the spawn boundary DETERMINISTICALLY at
 *       0 (all inline), 1, and a partial value — exercising the real join+inline recovery, no resource
 *       games — and asserts the correct VMK still opens. Positive control of the error path: must OPEN.
 *
 * Wired into build_and_verify.sh as step [99].
 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <cmath>
extern "C" {
#include "Common/Keyslot.h"
#include "Common/KeyslotStore.h"
#include "Crypto/Sha2.h"
}
#include "Volume/KeyslotParallelExecutor.h"   /* the REAL executor; -DVC_KS_PAR_TEST_HOOK exposes the hook */
extern "C" int g_vcKsParMaxSpawn = -1;        /* storage for the test hook; -1 = unlimited (production) */

/* ---- test KDF (PBKDF2-HMAC-SHA256; same shape as keyslot_store_test.c) ---- */
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
extern "C" void test_kdf (const unsigned char *pw, int pwl, const unsigned char *salt, int sl,
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

#define AREA_SLOTS 63
static unsigned char g_area[AREA_SLOTS * KEYSLOT_TABLE_STRIDE];
extern "C" int    mem_read  (void *c, uint64 off, unsigned char *b, size_t n)       { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(b, g_area+off, n); return 0; }
extern "C" int    mem_write (void *c, uint64 off, const unsigned char *b, size_t n) { (void)c; if (off+n > sizeof(g_area)) return -1; memcpy(g_area+off, b, n); return 0; }
extern "C" uint64 mem_size  (void *c)                                               { (void)c; return sizeof(g_area); }
static uint32_t g_rng = 0xBADC0DEu;
extern "C" void det_rand (unsigned char *p, size_t n) { size_t i; for (i=0;i<n;i++){ g_rng=g_rng*1664525u+1013904223u; p[i]=(unsigned char)(g_rng>>24);} }

static double now_s () { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (double)t.tv_sec + (double)t.tv_nsec*1e-9; }

int main ()
{
	KeyslotArea area; KeyslotStoreCfg cfg;
	unsigned char vmk[64], out[64];
	const unsigned int COST = 20000;   /* per-slot ~ms so KDF work dominates thread-spawn */
	const int N = 40, LAST = AREA_SLOTS - 1;
	int i, r, okrec0, oklast, all = 1;
	double s0[64], sl[64];

	for (i=0;i<64;i++) vmk[i]=(unsigned char)(0x40+i);
	area.read=mem_read; area.write=mem_write; area.size=mem_size; area.ctx=0;
	memset(&cfg,0,sizeof(cfg)); cfg.kdf=test_kdf; cfg.cost=COST; cfg.vmkLen=64; cfg.maxSlots=AREA_SLOTS; cfg.randBytes=det_rand; cfg.backend=KSB_HEADER;

	memset(g_area,0,sizeof(g_area));
	for (i=0;i<AREA_SLOTS;i++) { char pw[16]; int n=snprintf(pw,sizeof(pw),"pass-%d",i);
		if (KeyslotAdd(&cfg,&area,(const unsigned char*)pw,n,0,vmk) < 0) { printf("  enroll slot %d FAILED\n",i); return 1; } }
	printf("[setup] enrolled %d slots via the REAL VolumeKeyslotParallelFor, KDF cost=%u\n", AREA_SLOTS, COST);

	/* (A) correctness: byte-identical VMK at BOTH ends (catches an i*ct regression at slot >= 1) */
	{ char p[16]; int n=snprintf(p,sizeof(p),"pass-%d",0);    memset(out,0,sizeof out);
	  KeyslotOpenParallel(&cfg,&area,(const unsigned char*)p,n,out,0,VolumeKeyslotParallelFor); okrec0=(memcmp(out,vmk,cfg.vmkLen)==0); }
	{ char p[16]; int n=snprintf(p,sizeof(p),"pass-%d",LAST); memset(out,0,sizeof out);
	  KeyslotOpenParallel(&cfg,&area,(const unsigned char*)p,n,out,0,VolumeKeyslotParallelFor); oklast=(memcmp(out,vmk,cfg.vmkLen)==0); }
	printf("  VMK recovered at slot 0   byte-identical to enrolled : %s\n", okrec0?"YES":"NO");
	printf("  VMK recovered at slot %-3d byte-identical to enrolled : %s\n", LAST, oklast?"YES":"NO");

	/* (B) exception-safety / EAGAIN recovery: force the spawn boundary at 0 (all inline), 1, and partial,
	   and assert the correct VMK STILL opens through the real executor's join+inline fallback. */
	int caps[4] = {0, 1, 8, -1};   /* 0=all inline, 1=one thread + inline rest, 8=partial, -1=unlimited */
	for (i=0;i<4;i++) {
		char p[16]; int n=snprintf(p,sizeof(p),"pass-%d",LAST); int ok;
		g_vcKsParMaxSpawn = caps[i];
		memset(out,0,sizeof out);
		KeyslotOpenParallel(&cfg,&area,(const unsigned char*)p,n,out,0,VolumeKeyslotParallelFor);
		ok = (memcmp(out,vmk,cfg.vmkLen)==0);
		printf("  EAGAIN fallback maxspawn=%-2d : slot %d VMK recovered : %s\n", caps[i], LAST, ok?"YES":"NO");
		if (!ok) all = 0;
	}
	g_vcKsParMaxSpawn = -1;   /* production behaviour for the timing below */

	/* (A) timing: interleave match@0 / match@last, N reps, CLOCK_MONOTONIC */
	for (r=0;r<N;r++) {
		char p0[16],pl[16]; int n0=snprintf(p0,sizeof(p0),"pass-%d",0), nl=snprintf(pl,sizeof(pl),"pass-%d",LAST);
		double a,b;
		a=now_s(); KeyslotOpenParallel(&cfg,&area,(const unsigned char*)p0,n0,out,0,VolumeKeyslotParallelFor); b=now_s(); s0[r]=b-a;
		a=now_s(); KeyslotOpenParallel(&cfg,&area,(const unsigned char*)pl,nl,out,0,VolumeKeyslotParallelFor); b=now_s(); sl[r]=b-a;
	}
	{ double m0=0,ml=0,sd0=0,sdl=0;
	  for (r=0;r<N;r++){ m0+=s0[r]; ml+=sl[r]; } m0/=N; ml/=N;
	  for (r=0;r<N;r++){ sd0+=(s0[r]-m0)*(s0[r]-m0); sdl+=(sl[r]-ml)*(sl[r]-ml); } sd0=sqrt(sd0/N); sdl=sqrt(sdl/N);
	  double dmean = m0>ml?m0-ml:ml-m0, noise = sd0>sdl?sd0:sdl;
	  printf("  match@slot0   : mean=%.6fs sd=%.6fs (n=%d)\n", m0,sd0,N);
	  printf("  match@slot%-3d : mean=%.6fs sd=%.6fs (n=%d)\n", LAST, ml,sdl,N);
	  printf("  |mean0 - mean%d| = %.6fs ; max sd = %.6fs ; ratio = %.2f (position leak if >> 1)\n", LAST, dmean, noise, noise>0?dmean/noise:0.0);
	  int timing_ok = (dmean <= 3.0*noise);
	  int ok = okrec0 && oklast && all && timing_ok;
	  printf("\n  %s\n", ok
	      ? "KEYSLOT PARALLEL TIMING GATE PASSED (VMK identical at both ends + under EAGAIN fallbacks; position delta within noise)"
	      : "KEYSLOT PARALLEL TIMING GATE FAILED");
	  return ok ? 0 : 1;
	}
}
