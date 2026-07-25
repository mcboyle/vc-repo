/*
 * KeyslotParallelExecutor.h — the parallel-for executor for the constant-time keyslot auto-search
 * (Common/KeyslotStore.c KeyslotOpenParallel). Extracted into its own header so the ACTUAL product
 * executor is directly testable (verification/keyslot_parallel_timing_test) rather than a replica —
 * the pf seam exists to make the executor injectable, so it should not be trapped inside Volume.cpp.
 * This file is ONLY the executor; the scan/reduce and its constant-time property live in KeyslotStore.c.
 *
 * Gated behind VC_ENABLE_KEYSLOTS; a build without it never includes this.
 */
#ifndef TC_HEADER_Volume_KeyslotParallelExecutor
#define TC_HEADER_Volume_KeyslotParallelExecutor

#if defined(VC_ENABLE_KEYSLOTS)

#include <thread>
#include <vector>

#if defined(VC_KS_PAR_TEST_HOOK)
/* TEST-ONLY (never compiled into the product): caps how many threads are actually spawned, so the
   join + inline-fallback recovery can be exercised DETERMINISTICALLY at any boundary — 0 (all inline),
   1, nthreads-1 — with no RLIMIT_NPROC / cgroup games. <0 means unlimited = production behaviour. The
   defining TU (the test) provides the storage; the product never compiles this branch. */
extern "C" int g_vcKsParMaxSpawn;
#endif

/* CONTRACT: run body(ctx,i) for EVERY i in [0,n) exactly once, and return only after all have run.
 *
 * noexcept + total recovery are load-bearing, not defensive polish. This is invoked through a C function
 * pointer from KeyslotStore.c (compiled as C, no unwind tables): a C++ exception propagating across those
 * frames is UNDEFINED BEHAVIOUR. And std::thread's ctor THROWS std::system_error on EAGAIN (RLIMIT_NPROC /
 * cgroup pids.max / memory pressure); if that left slots unprocessed, the scan's mret[] would stay unset
 * and KeyslotOpen would return 0 = "wrong password" TO A USER WHOSE PASSPHRASE IS CORRECT. Three failure
 * modes are handled: (1) exception across the boundary -> catch(...); (2) a joinable std::thread that
 * destructs -> std::terminate -> the join loop is OUTSIDE the try and runs unconditionally; (3) push_back
 * reallocating and throwing after a thread was constructed -> reserve() upfront so no realloc can occur.
 * spawnedHi advances only after a successful spawn, so [spawnedHi, n) is exactly the uncovered tail and
 * runs inline. Every body runs exactly once whether 0, some, or all threads were created. */
extern "C" inline void VolumeKeyslotParallelFor (int n, void (*body) (void *, int), void *ctx) noexcept
{
	if (n <= 0) return;
	int spawnedHi = 0;                     // indices [0, spawnedHi) are owned by successfully-created threads
	std::vector<std::thread> ts;
	try
	{
		if (n > 1)
		{
			unsigned hw = std::thread::hardware_concurrency ();
			int nthreads = (int) (hw ? hw : 1u);            // hardware_concurrency() may return 0
			if (nthreads > n) nthreads = n;
			ts.reserve ((size_t) nthreads);                 // so push_back below never reallocates/throws
			int per = (n + nthreads - 1) / nthreads;
			for (int t = 0; t < nthreads; ++t)
			{
				int lo = t * per, hi = lo + per; if (hi > n) hi = n; if (lo >= hi) break;
#if defined(VC_KS_PAR_TEST_HOOK)
				if (g_vcKsParMaxSpawn >= 0 && t >= g_vcKsParMaxSpawn) break;   // deterministic "spawn failed at t"
#endif
				ts.push_back (std::thread ([=]() { for (int i = lo; i < hi; ++i) body (ctx, i); }));
				spawnedHi = hi;                             // advance ONLY after a successful spawn
			}
		}
	}
	catch (...) { /* a std::thread ctor threw; spawnedHi covers only the threads that were created */ }
	// Join every thread we created — OUTSIDE the try, so a mid-loop throw cannot skip it (a joinable
	// std::thread that destructs calls std::terminate).
	for (size_t k = 0; k < ts.size (); ++k) { try { if (ts[k].joinable ()) ts[k].join (); } catch (...) {} }
	// Run any index not covered by a spawned thread inline (all-inline, partial-spawn, and n==1 cases).
	// body() is a C function that does not throw, so this loop is exception-free.
	for (int i = spawnedHi; i < n; ++i) body (ctx, i);
}

#endif // VC_ENABLE_KEYSLOTS
#endif // TC_HEADER_Volume_KeyslotParallelExecutor
