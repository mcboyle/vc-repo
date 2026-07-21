/*
 * KeyScrub — see KeyScrub.h for the design and boundary.
 *
 * The RAM-encryption transform deliberately reuses VeraCrypt's own in-tree primitives — the real
 * t1ha2_atonce128 (Crypto/t1ha2.c) and ChaCha12 (Crypto/chacha256.c) — and reproduces the exact
 * construction of Common/Crypto.c::VcProtectMemory, so it is the same scheme the Windows driver
 * uses, only instantiated for the Linux/macOS application and parameterised for verification.
 */

#include "KeyScrub.h"

#if defined(VC_ENABLE_KEYSCRUB)

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "Crypto/t1ha.h"
#include "Crypto/chacha256.h"
#include "Crypto/chachaRng.h"

#if !defined(_WIN32)
#	include <pthread.h>
static pthread_mutex_t g_ksLock = PTHREAD_MUTEX_INITIALIZER;
#	define KS_LOCK()   pthread_mutex_lock (&g_ksLock)
#	define KS_UNLOCK() pthread_mutex_unlock (&g_ksLock)
#else
#	include <windows.h>
static CRITICAL_SECTION g_ksLock;
static LONG g_ksLockInit = 0;
static void ks_lock_ensure (void)
{
	if (InterlockedCompareExchange (&g_ksLockInit, 1, 0) == 0)
		InitializeCriticalSection (&g_ksLock);
}
#	define KS_LOCK()   (ks_lock_ensure(), EnterCriticalSection (&g_ksLock))
#	define KS_UNLOCK() LeaveCriticalSection (&g_ksLock)
#endif

/* ================================================================================================
 *  Secure wipe
 * ============================================================================================== */

void VcSecureWipe (volatile void *pbData, size_t cbData)
{
	volatile unsigned char *p = (volatile unsigned char *) pbData;
	if (!p)
		return;
	while (cbData--)
		*p++ = 0;
#if defined(__GNUC__) || defined(__clang__)
	/* deny the optimiser any freedom to treat the writes above as dead */
	__asm__ __volatile__ ("" ::: "memory");
#endif
}

/* ================================================================================================
 *  Process memory-hygiene lockdown
 * ============================================================================================== */

#if defined(__linux__)
#	include <sys/mman.h>       /* mlockall */
#	include <sys/resource.h>   /* setrlimit */
#	include <sys/prctl.h>      /* prctl */
#endif

int VcKeyMemoryLockdown (void)
{
	int applied = 0;
#if defined(__linux__) || defined(__APPLE__)
	if (mlockall (MCL_CURRENT | MCL_FUTURE) == 0)
		applied |= VC_LOCKDOWN_MLOCK;    /* keys never swapped to disk (needs privilege) */
#endif
#if defined(__linux__) || defined(__APPLE__)
	{
		struct rlimit rl;
		rl.rlim_cur = 0; rl.rlim_max = 0;
		if (setrlimit (RLIMIT_CORE, &rl) == 0)
			applied |= VC_LOCKDOWN_NO_CORE;   /* a crash cannot dump keys to a core file */
	}
#endif
#if defined(__linux__)
	if (prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) == 0)
		applied |= VC_LOCKDOWN_NO_DUMP;      /* blocks ptrace attach / core generation */
#endif
	return applied;
}

/* ================================================================================================
 *  Scrub registry
 * ============================================================================================== */

typedef struct
{
	void  *ptr;
	size_t len;
} KsRegion;

static KsRegion g_ksRegions[VC_SCRUB_MAX_REGIONS];
static int      g_ksRegionCount = 0;

int VcScrubRegister (void *pbData, size_t cbData)
{
	int i, rc = -1;
	if (!pbData || !cbData)
		return 0;
	KS_LOCK ();
	/* update in place if already present */
	for (i = 0; i < g_ksRegionCount; i++)
	{
		if (g_ksRegions[i].ptr == pbData)
		{
			g_ksRegions[i].len = cbData;
			rc = 0;
			goto done;
		}
	}
	if (g_ksRegionCount < VC_SCRUB_MAX_REGIONS)
	{
		g_ksRegions[g_ksRegionCount].ptr = pbData;
		g_ksRegions[g_ksRegionCount].len = cbData;
		g_ksRegionCount++;
		rc = 0;
	}
done:
	KS_UNLOCK ();
	return rc;
}

void VcScrubUnregister (void *pbData)
{
	int i;
	if (!pbData)
		return;
	KS_LOCK ();
	for (i = 0; i < g_ksRegionCount; i++)
	{
		if (g_ksRegions[i].ptr == pbData)
		{
			/* compact: move the last entry into this slot */
			g_ksRegions[i] = g_ksRegions[g_ksRegionCount - 1];
			g_ksRegions[g_ksRegionCount - 1].ptr = 0;
			g_ksRegions[g_ksRegionCount - 1].len = 0;
			g_ksRegionCount--;
			break;
		}
	}
	KS_UNLOCK ();
}

int VcScrubAll (void)
{
	int i, n;
	KS_LOCK ();
	n = g_ksRegionCount;
	for (i = 0; i < n; i++)
		VcSecureWipe (g_ksRegions[i].ptr, g_ksRegions[i].len);
	KS_UNLOCK ();
	return n;
}

int VcScrubRegionCount (void)
{
	int n;
	KS_LOCK ();
	n = g_ksRegionCount;
	KS_UNLOCK ();
	return n;
}

/* ================================================================================================
 *  RAM encryption at rest
 * ============================================================================================== */

void VcKsRamTransform (const unsigned char *area, size_t areaLen,
                       uint64 hashSeedMask, uint64 cipherIVMask,
                       uint64 areaBase, uint64 encID,
                       unsigned char *buf, size_t bufLen)
{
	uint64        hashSeed, hashHigh = 0, hashLow, cipherIV;
	uint64        pbKey[4];
	ChaCha256Ctx  ctx;

	if (!area || !areaLen || !buf || !bufLen)
		return;

	/* derive a 128-bit hash of the whole key-derivation area, seeded by (area address + encID) */
	hashSeed = (areaBase + encID) ^ hashSeedMask;
	hashLow  = t1ha2_atonce128 (&hashHigh, area, areaLen, hashSeed);

	/* expand the 128-bit hash into a 256-bit ChaCha key, then whiten it with ChaCha12 */
	pbKey[0] = hashLow;
	pbKey[1] = hashHigh;
	pbKey[2] = hashLow ^ hashHigh;
	pbKey[3] = hashLow + hashHigh;

	ChaCha256Init    (&ctx, (unsigned char *) pbKey, (unsigned char *) &hashSeed, 12);
	ChaCha256Encrypt (&ctx, (unsigned char *) pbKey, sizeof (pbKey), (unsigned char *) pbKey);

	/* encrypt the secret in place with the whitened key and an address-bound IV */
	cipherIV = (areaBase + encID) ^ cipherIVMask;
	ChaCha256Init    (&ctx, (unsigned char *) pbKey, (unsigned char *) &cipherIV, 12);
	ChaCha256Encrypt (&ctx, buf, bufLen, buf);

	VcSecureWipe (pbKey, sizeof (pbKey));
	VcSecureWipe (&ctx, sizeof (ctx));
	VcSecureWipe (&hashSeed, sizeof (hashSeed));
	VcSecureWipe (&hashLow, sizeof (hashLow));
	VcSecureWipe (&hashHigh, sizeof (hashHigh));
	VcSecureWipe (&cipherIV, sizeof (cipherIV));
}

/* process-wide key-derivation area (mirrors Common/Crypto.c static state, but app-owned) */
static unsigned char *g_ksArea      = 0;
static size_t         g_ksAreaLen   = 0;
static uint64         g_ksHashMask  = 0;
static uint64         g_ksIVMask    = 0;
static uint64         g_ksAreaBase  = 0;   /* value fed into the address-bound terms */

#define VC_KS_AREA_SIZE (1024 * 1024)

static int ks_area_from_rng (ChaCha20RngCtx *ctx, size_t areaLen, uint64 areaBase)
{
	VcKsRamProtectShutdown ();

	g_ksArea = (unsigned char *) malloc (areaLen);
	if (!g_ksArea)
		return 0;
	g_ksAreaLen  = areaLen;
	g_ksAreaBase = areaBase;

	ChaCha20RngGetBytes (ctx, g_ksArea, areaLen);
	ChaCha20RngGetBytes (ctx, (unsigned char *) &g_ksHashMask, sizeof (g_ksHashMask));
	ChaCha20RngGetBytes (ctx, (unsigned char *) &g_ksIVMask,   sizeof (g_ksIVMask));
	return 1;
}

int VcKsRamProtectInit (GetRandSeedFn rngCallback)
{
	ChaCha20RngCtx ctx;
	unsigned char  seed[CHACHA20RNG_KEYSZ + CHACHA20RNG_IVSZ];
	int            ok;

	if (!rngCallback)
		return 0;
	rngCallback (seed, sizeof (seed));
	ChaCha20RngInit (&ctx, seed, rngCallback, 0);

	/* bind the address-derived term to the real heap address, as upstream does */
	ok = ks_area_from_rng (&ctx, VC_KS_AREA_SIZE, 0);
	if (ok)
		g_ksAreaBase = (uint64) (uintptr_t) g_ksArea;

	VcSecureWipe (seed, sizeof (seed));
	VcSecureWipe (&ctx, sizeof (ctx));
	return ok;
}

int VcKsRamProtectInitFixed (const unsigned char seed40[40])
{
	ChaCha20RngCtx ctx;
	int            ok;

	if (!seed40)
		return 0;
	/* NULL callback: the RNG runs as a pure PRG of the fixed seed (no reseed), so the area and
	   masks are fully determined — a reproducible vector. areaBase is pinned to a constant. */
	ChaCha20RngInit (&ctx, seed40, 0, 0);
	ok = ks_area_from_rng (&ctx, 4096, UINT64_C(0x1122334455667788));
	VcSecureWipe (&ctx, sizeof (ctx));
	return ok;
}

int VcKsRamProtectReady (void)
{
	return g_ksArea != 0;
}

void VcKsRamProtect (unsigned char *buf, size_t bufLen)
{
	if (!g_ksArea || !buf || !bufLen)
		return;
	VcKsRamTransform (g_ksArea, g_ksAreaLen, g_ksHashMask, g_ksIVMask,
	                  g_ksAreaBase, (uint64) (uintptr_t) buf, buf, bufLen);
}

void VcKsRamUnprotect (unsigned char *buf, size_t bufLen)
{
	/* stream cipher: decryption is the same operation */
	VcKsRamProtect (buf, bufLen);
}

void VcKsRamProtectShutdown (void)
{
	if (g_ksArea)
	{
		VcSecureWipe (g_ksArea, g_ksAreaLen);
		free (g_ksArea);
		g_ksArea = 0;
	}
	g_ksAreaLen  = 0;
	g_ksAreaBase = 0;
	VcSecureWipe (&g_ksHashMask, sizeof (g_ksHashMask));
	VcSecureWipe (&g_ksIVMask,   sizeof (g_ksIVMask));
}

/*
 * HKFScrubActiveConfig fallback. The KeyScrub event manager (KeyScrubEvents.cpp) calls
 * HKFScrubActiveConfig() on every scrub trigger so any live hardware/threshold factor secret is
 * wiped. The real definition lives in HardwareKeyFactor.c, which is only compiled when the HKF
 * feature is enabled. A KEYSCRUB build *without* HKF has no factor to scrub, so provide a no-op with
 * the same C linkage here to satisfy the call site. Guarded on !VC_ENABLE_HKF so the two definitions
 * never collide. The header declares it under VC_ENABLE_KEYSCRUB, so the prototype is in scope.
 */
#if !defined(VC_ENABLE_HKF)
void HKFScrubActiveConfig (void) { }
#endif

#endif /* VC_ENABLE_KEYSCRUB */
