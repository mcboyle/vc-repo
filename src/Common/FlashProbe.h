/*
 * FlashProbe — runtime media check for hidden-volume deniability (research batch-2 C3).
 *
 * Hidden-volume deniability does NOT survive flash: FTL remapping, wear levelling and
 * over-provisioning leave sub-block residue that chip-off recovers, and TRIM/discard in the data path
 * can reveal which blocks are unused. Deniability is also defeated on rotational media by a logical
 * two-snapshot changed-block classifier. So on creating/mounting a hidden or decoy volume the caller
 * should warn the user unless the device verifies clean on ALL checks, and warn on ANY unknown input.
 *
 * FAIL CLOSED is the contract: every function returns a bitmask of VC_FLASH_WARN_* reasons, and 0
 * ("clean") is produced ONLY when a check positively confirms the safe condition. Missing files,
 * unreadable values, unparseable buffers, reserved/unknown encodings, and unsupported platforms all
 * set a warn bit — silence is never treated as safe.
 *
 * The decoders take caller-supplied buffers / an injectable sysfs root so they are unit-testable
 * without real devices (verification/flash_probe_test.c). Actual device enumeration
 * (FlashProbeDevice) is platform glue: the Linux path is exercised against fixture trees; the
 * Windows (IOCTL_STORAGE_QUERY_PROPERTY) and macOS (no reliable rotational flag -> always warn) paths
 * are real-build only. Gated behind VC_ENABLE_FLASH_WARN; default builds are unaffected.
 */

#ifndef TC_HEADER_Common_FlashProbe
#define TC_HEADER_Common_FlashProbe

#if defined(VC_ENABLE_FLASH_WARN)

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Warn reasons (bitmask). 0 == VC_FLASH_CLEAN == deniability-safe on this axis. */
#define VC_FLASH_CLEAN            0
#define VC_FLASH_WARN_ROTATIONAL  (1u << 0)  /* not confirmed rotational (SSD / flash / unknown media) */
#define VC_FLASH_WARN_TRIM        (1u << 1)  /* TRIM/discard supported, or deterministic read-after-trim */
#define VC_FLASH_WARN_THIN        (1u << 2)  /* thin-provisioned / dedup / SMR / ZNS underneath */
#define VC_FLASH_WARN_UNKNOWN     (1u << 3)  /* could not determine — fail closed */

/* ATA IDENTIFY DEVICE (512 bytes = 256 little-endian u16 words). Warns if TRIM is supported
   (word 169 bit 0) or deterministic read-after-TRIM is advertised (word 69 bit 14 DRAT, bit 5 RZAT).
   Returns VC_FLASH_WARN_UNKNOWN if id512 is NULL. Never returns CLEAN on a short/garbage buffer the
   caller mislabels — the caller must pass a full 512-byte IDENTIFY. */
unsigned int FlashProbeAtaTrim (const unsigned char *id512);

/* NVMe Identify Namespace DLFEAT byte (byte 33). bits 2:0 == 001b (reads 0x00 after deallocate) or
   010b (reads 0xFF after deallocate) => deterministic read-after-deallocate => VC_FLASH_WARN_TRIM.
   000b (deallocate behaviour not reported) => CLEAN on this axis (no deterministic tell; the rotational
   axis, which warns on any SSD, carries the flash decision). Reserved 011b..111b => VC_FLASH_WARN_UNKNOWN
   (fail closed on an encoding this decoder does not understand). */
unsigned int FlashProbeNvmeDlfeat (unsigned char dlfeat);

/* Linux rotational probe. Reads <sysroot>/block/<dev>/queue/rotational; returns CLEAN only when it
   reads exactly "1" (confirmed rotational). "0", missing file, unreadable, or any other content =>
   VC_FLASH_WARN_ROTATIONAL. Also folds in a discard check: if
   <sysroot>/block/<dev>/queue/discard_granularity exists and is non-zero, discard is in the data path
   => adds VC_FLASH_WARN_TRIM. sysroot lets tests inject a fixture tree (pass "/sys" in production);
   dev is a leaf name like "sda" (caller strips partitions / resolves the base device). */
unsigned int FlashProbeRotationalSysfs (const char *sysroot, const char *dev);

/* Aggregate a set of already-collected per-axis results into the final decision. Purely combines
   bits (OR) and is the single place the "clean == every axis positively clean" rule lives, so the
   fail-closed contract is testable in isolation. Pass VC_FLASH_WARN_UNKNOWN for any axis you could
   not evaluate. */
unsigned int FlashProbeAggregate (unsigned int rotational, unsigned int trim, unsigned int thin);

/* True when the decision is deniability-safe (i.e. warn == VC_FLASH_CLEAN). Even then the caller must
   still surface the multi-snapshot caveat (see FlashProbeCaveat). */
int FlashProbeIsClean (unsigned int warn);

/* A stable human-readable caveat string the caller prints EVEN ON A CLEAN PASS: deniability still
   fails on a rotational disk against an adversary who images the device twice. */
const char *FlashProbeCaveat (void);

/* Platform device probe (real-build glue; not exercised in the sandbox except the Linux fixture path).
   Returns the aggregated warn bitmask for a named base device. Linux: FlashProbeRotationalSysfs over
   "/sys" plus best-effort ATA/NVMe identify. macOS: no reliable rotational flag => always warns.
   Windows: IOCTL_STORAGE_QUERY_PROPERTY seek-penalty descriptor. */
unsigned int FlashProbeDevice (const char *dev);

#ifdef __cplusplus
}
#endif

#endif /* VC_ENABLE_FLASH_WARN */
#endif /* TC_HEADER_Common_FlashProbe */
