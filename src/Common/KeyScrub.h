/*
 * KeyScrub — cross-platform in-RAM key hygiene for the Linux/macOS application.
 *
 * VeraCrypt's own RAM-key-encryption and key-erase-on-shutdown (Common/Crypto.c VcProtectKeys /
 * ClearSecurityParameters) are wired up only inside the Windows kernel driver. On Linux and macOS
 * the application never initialises them, so any secret this fork holds in user space — most
 * importantly the reconstructed Shamir secret and other HardwareKeyFactor material — sits in the
 * clear in RAM for the whole process lifetime, exposed to cold-boot and DMA (Thunderbolt/FireWire)
 * capture. This module closes that gap for user-space secrets. It does NOT (and cannot) reach the
 * mounted master key, which lives in the kernel device-mapper once a volume is mounted; see
 * docs/MEMORY-SCRUB.md for that boundary.
 *
 * Two things live here:
 *   1. A secure-wipe primitive and a small registry of live secret regions, so a single call
 *      (VcScrubAll) erases every registered secret on an event (unmount / idle / screen-lock /
 *      new-device-connect). The wipe resists dead-store elimination.
 *   2. A RAM-encryption-at-rest transform that mirrors the Windows VcProtectMemory scheme: a large
 *      random "key-derivation area" is hashed with t1ha2 to derive a per-region ChaCha12 key that
 *      encrypts the secret in place, so the plaintext secret is not resident between uses. The core
 *      transform (VcKsRamTransform) is a pure function of explicit parameters so it can be proven
 *      byte-for-byte against an independent reimplementation.
 *
 * Everything is compiled only when -DVC_ENABLE_KEYSCRUB is set; a build without it is byte-for-byte
 * stock. EXPERIMENTAL — a mitigation, not a guarantee; a determined attacker with live DMA can still
 * race the window in which a secret is revealed for use.
 */

#ifndef TC_HEADER_Common_KeyScrub
#define TC_HEADER_Common_KeyScrub

#include "Tcdefs.h"

#if defined(VC_ENABLE_KEYSCRUB)

#include "Crypto/chachaRng.h"   /* GetRandSeedFn */

#if defined(__cplusplus)
extern "C" {
#endif

/* ---- secure wipe ------------------------------------------------------------------------- */

/* Zero cbData bytes at pbData in a way the compiler may not elide. Safe on NULL/0. */
void VcSecureWipe (volatile void *pbData, size_t cbData);

/* ---- process memory-hygiene lockdown ----------------------------------------------------- */

/* Bits returned by VcKeyMemoryLockdown reporting which protections were applied. */
#define VC_LOCKDOWN_MLOCK     0x01   /* mlockall: pages will not be swapped out */
#define VC_LOCKDOWN_NO_CORE   0x02   /* RLIMIT_CORE = 0: no core dump can leak keys */
#define VC_LOCKDOWN_NO_DUMP   0x04   /* PR_SET_DUMPABLE 0: no ptrace attach / no core */

/*
 * Best-effort process hardening against key material leaking OUT of RAM: prevent swapping (so a key
 * never reaches an unencrypted swap file), disable core dumps, and mark the process non-dumpable
 * (blocks ptrace-based live extraction). Scrubbing RAM does not help if the key already reached swap
 * or a hibernation image — call this once at startup, before any secret is derived. Returns a bitmask
 * of the VC_LOCKDOWN_* protections that succeeded (mlockall commonly needs privilege and may be 0).
 * NOTE: hibernation writes the whole of RAM to disk and is NOT prevented by mlock — warn users to
 * disable hibernation on machines holding mounted volumes (see docs/MEMORY-SCRUB.md).
 */
int VcKeyMemoryLockdown (void);

/* ---- swap / hibernation exposure detector ------------------------------------------------ */

/* Bits returned by VcSwapHibernateStatus reporting RAM-to-disk exposure that mlock cannot prevent. */
#define VC_HIBERNATE_SWAP_ACTIVE  0x01  /* an active swap area exists: paged-out RAM can reach disk */
#define VC_HIBERNATE_SUPPORTED    0x02  /* kernel advertises suspend-to-disk: hibernation writes ALL
                                           of RAM (mlocked pages included) to the swap device */

/*
 * mlockall stops routine swapping, but two things still push key material to disk and it cannot help:
 * an already-active swap area (a key paged out BEFORE lockdown, or by a sibling process) and
 * hibernation (suspend-to-disk snapshots the whole of RAM, mlocked pages included). This detector
 * reports both so the caller can print a loud warning while volumes are mounted. Best-effort and
 * read-only; on a platform without /proc + /sys it simply returns 0 (unknown, not "safe").
 * Returns a bitmask of the VC_HIBERNATE_* bits.
 */
int VcSwapHibernateStatus (void);

/* Testable core of VcSwapHibernateStatus: parses the given files instead of the real /proc + /sys, so
 * the verification harness can drive it with fixtures. Pass the real paths for production behaviour.
 * A NULL path is treated as "file absent" (that bit is not set). */
int VcSwapHibernateStatusFrom (const char *swapsPath, const char *powerStatePath);

/* ---- scrub registry ---------------------------------------------------------------------- */

/* Maximum number of secret regions tracked at once. Small and fixed: no allocation on the scrub
   path, so VcScrubAll stays usable from constrained contexts. */
#define VC_SCRUB_MAX_REGIONS 64

/* Register / unregister a live secret region. Registering the same pointer again updates its
   length. Unregistering a pointer that is not present is a no-op. Both are thread-safe. */
int  VcScrubRegister   (void *pbData, size_t cbData);   /* returns 0 on success, -1 if table full */
void VcScrubUnregister (void *pbData);

/* Wipe every currently-registered region (does not unregister them — a re-revealed secret stays
   tracked). Returns the number of regions wiped. Thread-safe. */
int  VcScrubAll (void);

/* Number of regions currently registered (diagnostics/tests). */
int  VcScrubRegionCount (void);

/* ---- RAM encryption at rest (mirrors Common/Crypto.c VcProtectMemory) --------------------- */

/*
 * Pure core transform, exposed for verification. Reproduces the VcProtectMemory construction with
 * every input passed explicitly instead of read from process-global state:
 *
 *   hashSeed = (areaBase + encID) ^ hashSeedMask
 *   (hashLow,hashHigh) = t1ha2_atonce128(area, areaLen, hashSeed)
 *   key = ChaCha12_key_whiten([hashLow, hashHigh, hashLow^hashHigh, hashLow+hashHigh])
 *   cipherIV = (areaBase + encID) ^ cipherIVMask
 *   buf ^= ChaCha12_keystream(key, cipherIV)
 *
 * It is its own inverse (stream cipher): calling it twice with identical parameters restores the
 * plaintext. All multi-byte values are serialised little-endian, matching the x86_64/ARM64 targets
 * and t1ha2's fetch64_le. areaBase lets a test pin the address-derived term to a constant for a
 * reproducible vector; the live store passes the real area address (anti-forensic address binding,
 * as upstream does).
 */
void VcKsRamTransform (const unsigned char *area, size_t areaLen,
                       uint64 hashSeedMask, uint64 cipherIVMask,
                       uint64 areaBase, uint64 encID,
                       unsigned char *buf, size_t bufLen);

/* Initialise the process-wide key-derivation area from a seed callback (production: a CSPRNG).
   Returns TRUE on success. Idempotent-safe: a second call rebuilds the area. */
int  VcKsRamProtectInit (GetRandSeedFn rngCallback);

/* Deterministic init for tests/regression vectors: the 40-byte seed fully determines the area and
   masks, and areaBase is pinned to a fixed constant, so the protected output is reproducible. */
int  VcKsRamProtectInitFixed (const unsigned char seed40[40]);

int  VcKsRamProtectReady (void);

/* Encrypt / decrypt a region in place against the active area (no-op if the area is not initialised
   — the caller still gets scrub coverage via the registry). Decrypt == Encrypt. */
void VcKsRamProtect   (unsigned char *buf, size_t bufLen);
void VcKsRamUnprotect (unsigned char *buf, size_t bufLen);

/* Wipe and free the key-derivation area and masks. */
void VcKsRamProtectShutdown (void);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_KEYSCRUB */

#endif /* TC_HEADER_Common_KeyScrub */
