/*
 * areafile_fuzz.c — fuzz the deniable-extent geometry of KeyslotAreaFile.c (ROI item 32),
 * under gcc ASan+UBSan.
 *
 * KeyslotAreaBindDeniable turns adversarial volume geometry (freeStart, freeEnd, hiddenReservedStart)
 * into a bounded keyslot window. Its security-critical invariant: a window it ACCEPTS must never
 * extend into the hidden-volume region — otherwise bare keyslot records would overwrite the hidden
 * volume. This driver feeds tens of thousands of adversarial geometries (overlapping, reversed, zero,
 * near-overflow) and, on every accepted binding, asserts:
 *      base >= freeStart,  base+len <= freeEnd,  len >= KEYSLOT_TABLE_STRIDE,
 *      base+len does not overflow, and (crucially) base+len <= hiddenReservedStart when it is set.
 * A second pass does bounded reads/writes over a valid header-slack window on a REAL file so ASan/UBSan
 * cover the stdio path itself.
 *
 * Deterministic (fixed seed). VC_AREAFILE_NEGCTL is the negative control: a buggy clamp that ignores
 * hiddenReservedStart produces a window reaching into hidden space, and the invariant check MUST flag
 * it — proving the oracle would catch a real clamping regression.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "Common/KeyslotAreaFile.h"

static uint64_t g_s = 0x0f1e2d3c4b5a6978ULL;
static uint64_t xr (void) { uint64_t x=g_s; x^=x<<13; x^=x>>7; x^=x<<17; g_s=x; return x; }

/* adversarial magnitudes: small, near a 1 GiB "volume", and near UINT64_MAX */
static uint64 wild (void)
{
	switch (xr() % 5) {
		case 0:  return xr() % 4096;
		case 1:  return (1ULL<<30) + (xr() % 4096);
		case 2:  return UINT64_MAX - (xr() % 4096);
		case 3:  return 0;
		default: return xr();
	}
}

/* The invariant a bound deniable window must satisfy. Returns 0 if OK, else a reason code. */
static int check_window (uint64 base, uint64 len, uint64 fs, uint64 fe, uint64 hr)
{
	unsigned __int128 endv = (unsigned __int128) base + len;
	if (len < KEYSLOT_TABLE_STRIDE)          return 1;   /* too small to be usable */
	if (base < fs)                           return 2;   /* started before the free extent */
	if (endv < base)                         return 3;   /* base+len overflow */
	if (endv > (unsigned __int128) fe)       return 4;   /* ran past the free extent */
	if (hr != 0 && endv > (unsigned __int128) hr) return 5;   /* INTO HIDDEN SPACE — the critical one */
	return 0;
}

#if defined(VC_AREAFILE_NEGCTL)
/* buggy clamp: ignores hiddenReservedStart, so the window can reach into hidden space */
static int buggy_bind_deniable (KeyslotArea *area, KeyslotAreaFile *ctx,
                                uint64 freeStart, uint64 freeEnd, uint64 hiddenReservedStart)
{
	(void) hiddenReservedStart;
	if (freeStart >= freeEnd || freeEnd - freeStart < KEYSLOT_TABLE_STRIDE) return -1;
	KeyslotAreaBindWindow (area, ctx, freeStart, freeEnd - freeStart);
	return 0;
}
#endif

int main (void)
{
	KeyslotAreaFile ctx;
	KeyslotArea area;
	long it, iters = 40000;
	int bugs = 0;

	memset (&ctx, 0, sizeof (ctx));   /* no file needed for the geometry pass */

#if defined(VC_AREAFILE_NEGCTL)
	{
		/* construct a case where the free extent overruns the hidden start; the buggy clamp accepts a
		   window into hidden space and the invariant check must catch it. */
		uint64 fs = 1000, hr = 5000, fe = 100000;   /* freeEnd far past hr */
		int r = buggy_bind_deniable (&area, &ctx, fs, fe, hr);
		if (r == 0) {
			int reason = check_window (ctx.base, ctx.len, fs, fe, hr);
			printf ("NEGCTL buggy clamp -> window [%llu,%llu); invariant reason=%d (5 == into hidden)\n",
			        (unsigned long long) ctx.base, (unsigned long long)(ctx.base + ctx.len), reason);
			return (reason == 5) ? 0 : 1;   /* exit 0 == the check correctly flagged the hidden-space escape */
		}
		printf ("NEGCTL: buggy clamp unexpectedly rejected the case\n");
		return 1;
	}
#else
	/* ---- pass 1: adversarial deniable geometry ---- */
	for (it = 0; it < iters; it++)
	{
		uint64 fs = wild (), fe = wild (), hr = (xr() & 1) ? 0 : wild ();
		int r = KeyslotAreaBindDeniable (&area, &ctx, fs, fe, hr);
		if (r == 0) {
			int reason = check_window (ctx.base, ctx.len, fs, fe, hr);
			if (reason) {
				printf ("BUG: accepted deniable window violates invariant (reason=%d) fs=%llu fe=%llu hr=%llu base=%llu len=%llu\n",
				        reason, (unsigned long long) fs, (unsigned long long) fe, (unsigned long long) hr,
				        (unsigned long long) ctx.base, (unsigned long long) ctx.len);
				bugs++; break;
			}
		}
	}

	/* ---- pass 2: bounded stdio over a valid header-slack window (ASan/UBSan on the read/write path) ---- */
	if (!bugs)
	{
		const char *path = "/tmp/areafile_fuzz.bin";
		FILE *f = fopen (path, "w+b");
		if (f) {
			unsigned char blk[70000];
			size_t i; for (i = 0; i < sizeof (blk); i++) blk[i] = (unsigned char) xr();
			fwrite (blk, 1, sizeof (blk), f); fclose (f);      /* 70000-byte "container": > 64K header */
			if (KeyslotAreaFileOpen (&ctx, path, 1) == 0) {
				unsigned char buf[2048];
				KeyslotAreaBindHeaderSlack (&area, &ctx);       /* window [512, 64K) */
				for (it = 0; it < 5000; it++) {
					uint64 off = xr() % (ctx.len + 64);
					size_t n = (size_t)(xr() % sizeof (buf)) + 1;
					if (xr() & 1) (void) area.read (area.ctx, off, buf, n);
					else          (void) area.write (area.ctx, off, buf, n);
				}
				KeyslotAreaFileClose (&ctx);
			}
			remove (path);
		}
	}

	if (bugs) { printf ("areafile fuzz: FAILED (%d invariant violations)\n", bugs); return 1; }
	printf ("areafile fuzz: %ld deniable-geometry iters + 5000 stdio ops, invariant held, no ASan/UBSan fault\n", iters);
	return 0;
#endif
}
