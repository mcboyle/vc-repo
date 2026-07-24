/*
 * V2Format — shippable core of the v2 on-disk format (docs/V2-FORMAT-SPEC.md, T1-1).
 *
 * Implements the two format-level operations the design fixes, in shipping C, gated behind
 * VC_ENABLE_V2FORMAT (default builds are byte-for-byte stock):
 *
 *   1. per-mode-keyed per-sector authentication + the mount-time MODE DISCOVERY that stores NO selector,
 *   2. the full-volume MAC-table layout math (slot width + offset formula).
 *
 * PRF: HMAC-SHA256 over the in-tree Crypto/Sha2.c — the fork's existing MAC workhorse (DuressToken,
 * KeyslotKdf), so this adds NO new crypto dependency. The step-[84] reference PoC proved the SAME format
 * logic with keyed-BLAKE3; the format is PRF-agnostic. keyed-BLAKE3 remains the target if a vetted
 * in-tree BLAKE3 is ever added (there is none today) — see docs/V2-FORMAT-SPEC.md "shipping PRF".
 *
 * Mode discrimination is by the KEY, not the ciphertext: the tag is over ciphertext (encrypt-then-MAC),
 * so recomputing sector 0's tag under each mode's domain-separated key is what identifies the wide-block
 * mode with nothing stored on disk — and binds the mode (anti-downgrade). See V2FormatDiscoverMode.
 *
 * This module is pure logic (no volume I/O, no VeraCrypt platform types — stdint only), so it unit-tests
 * standalone against an independent python reference (verification/v2format_module_test.c) and drops into
 * the C++ mount/create path unchanged. The on-disk PLACEMENT of the table (tail-of-data, clamped below a
 * hidden-volume start) and the C++ trial-mount wiring are the real-build integration layer that consumes
 * these functions.
 */

#ifndef TC_HEADER_Common_V2Format
#define TC_HEADER_Common_V2Format

#if defined(VC_ENABLE_V2FORMAT)

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define V2_MAC_TAG_LEN   16   /* per-sector tag AND MAC-table slot width (128-bit, truncated HMAC) */
#define V2_KEY_LEN       32   /* derived per-mode sub-key length */

/* Wide-block modes. The on-disk stored mode is deliberately NONE — it is recovered by trial at mount. */
typedef enum { V2_MODE_HCTR2 = 0, V2_MODE_ADIANTUM = 1, V2_MODE_NONE = -1 } V2Mode;

/* K_mac[mode] = HMAC-SHA256(masterKey, "VeraCrypt/v2/mac/" || mode)[0..V2_KEY_LEN]. Domain separation by
   mode is what lets the ciphertext tag double as the mount-time mode oracle + anti-downgrade binding. */
void V2FormatDeriveModeKey (const unsigned char *masterKey, int masterKeyLen, V2Mode mode,
                            unsigned char outKey[V2_KEY_LEN]);

/* tag = HMAC-SHA256(macKey, le64(index) || ciphertext)[0..V2_MAC_TAG_LEN]  (encrypt-then-MAC, the le64
   index is INSIDE the PRF input so a (ciphertext,tag) pair cannot be relocated to another sector). */
void V2FormatSectorTag (const unsigned char macKey[V2_KEY_LEN], uint64_t index,
                        const unsigned char *ct, size_t ctLen, unsigned char tag[V2_MAC_TAG_LEN]);

/* Constant-time verify (OR-accumulate, no early-out). Returns 1 iff the recomputed tag equals `tag`. */
int V2FormatSectorVerify (const unsigned char macKey[V2_KEY_LEN], uint64_t index,
                          const unsigned char *ct, size_t ctLen, const unsigned char tag[V2_MAC_TAG_LEN]);

/* Mount-time MODE DISCOVERY (stores nothing): recompute sector 0's tag under each mode's key; the mode
   whose key reproduces `storedTag` is the volume's mode. Returns V2_MODE_HCTR2 / V2_MODE_ADIANTUM, or
   V2_MODE_NONE when neither matches — the caller then falls through to a legacy v1 interpretation.
   A wrong master key (wrong password/factor) matches no mode -> V2_MODE_NONE, same as v1. */
V2Mode V2FormatDiscoverMode (const unsigned char *masterKey, int masterKeyLen,
                             const unsigned char *sector0Ct, size_t ctLen,
                             const unsigned char storedTag[V2_MAC_TAG_LEN]);

/* ---- MAC-table layout (resolves the slot-width + offset-formula sub-decisions) ----
 * One V2_MAC_TAG_LEN slot per data sector. The table sits at the TAIL of the data area so the FRONT of
 * the volume (header group + data start) stays byte-identical in structure to v1 — a v2 volume is not
 * distinguishable from v1 by its early layout (deniability). The usable data area shrinks by the table.
 */

/* Bytes a MAC table for `dataSectors` sectors occupies, rounded UP to a whole `sectorSize` boundary. */
uint64_t V2FormatMacTableBytes (uint64_t dataSectors, uint32_t sectorSize);

/* Given a data area of `totalDataBytes` at `sectorSize`, split it into the usable-data prefix and the
   MAC-table suffix: writes the usable data byte count to *usableBytesOut and the table's byte offset
   (from the start of the data area) to *tableOffsetOut. Returns 0 on success, non-zero if the volume is
   too small to hold even a minimal table (caller must reject such a volume for v2). */
int V2FormatSplitDataArea (uint64_t totalDataBytes, uint32_t sectorSize,
                           uint64_t *usableBytesOut, uint64_t *tableOffsetOut);

/* Byte offset of sector `index`'s slot, measured from the start of the MAC table. */
uint64_t V2FormatSlotOffset (uint64_t index);

/* Stable label used for the KDF domain separation of a given mode (for the caller / tests). */
const char *V2FormatModeLabel (V2Mode mode);

#ifdef __cplusplus
}
#endif

#endif /* VC_ENABLE_V2FORMAT */
#endif /* TC_HEADER_Common_V2Format */
