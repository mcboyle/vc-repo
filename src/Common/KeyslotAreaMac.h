/*
 * KeyslotAreaMac — area-level authentication tag for the keyslot table (ROI-TOP-50 item 42).
 *
 * Each keyslot RECORD is already an AEAD (KeyslotWrap/UnwrapCT), so a bit-flip in a record makes it
 * fail to open. What is NOT authenticated is the SET of records: an attacker can delete, truncate,
 * reorder, or splice in an old shorter copy of the table and every surviving record still verifies.
 * This module adds a keyed MAC over the whole labeled-slot region, stored in a small reserved trailer,
 * so tampering with the table's structure is detected after a successful open.
 *
 *   areaMac = HMAC-SHA256(K_area, "VCKSAREA1" || u32_be(slotCount) || region[0..regionLen))
 *   K_area  = HKDF-SHA256(VMK, salt=<empty>, info="keyslot-area-mac")   (option A: VMK-derived; no new
 *             stored secret — verified only AFTER a slot open has recovered the VMK)
 *
 * Trailer layout (written at a caller-chosen offset past the last slot stride):
 *   magic[9]="VCKSAREA1" || ver[1]=1 || slotCount[4 big-endian] || tag[32]         (KAM_TRAILER_SIZE)
 *
 * Scope: labeled backends only (KSB_HEADER / KSB_SIDECAR). The deniable backend must stay markerless
 * and is deliberately out of scope. Rollback to an older COMPLETE table is not defeated without
 * external monotonic state (a TPM NV counter) — documented, same limit as elsewhere.
 *
 * Gated behind VC_ENABLE_KEYSLOT_AREA_MAC (needs VC_ENABLE_KEYSLOTS); default build stays stock.
 */
#ifndef TC_HEADER_Common_KeyslotAreaMac
#define TC_HEADER_Common_KeyslotAreaMac

#include "Tcdefs.h"

#if defined(VC_ENABLE_KEYSLOT_AREA_MAC) && defined(VC_ENABLE_KEYSLOTS)

#include "KeyslotStore.h"   /* KeyslotArea, KEYSLOT_TABLE_STRIDE */

#if defined(__cplusplus)
extern "C" {
#endif

#define KAM_TRAILER_MAGIC   "VCKSAREA1"
#define KAM_TRAILER_MAGICLEN 9
#define KAM_TRAILER_VER      1
#define KAM_TRAILER_SIZE     (KAM_TRAILER_MAGICLEN + 1 + 4 + 32)   /* magic+ver+count+tag = 46 */

/* Result codes. */
#define KAM_OK          0
#define KAM_TAMPERED  (-1)   /* trailer present but the MAC does not verify (tamper/rollback/wrong key) */
#define KAM_NO_TRAILER (-2)  /* no trailer: an old, unauthenticated area — caller warns and continues   */
#define KAM_ERR_IO    (-3)   /* area read/write failed                                                  */

/* Derive the area-MAC key from the volume master key: HKDF-SHA256(VMK) -> kArea[32]. */
void KeyslotAreaMacDeriveKey (const unsigned char *vmk, int vmkLen, unsigned char kArea[32]);

/* Compute the area MAC over the first regionLen bytes of the area (the labeled-slot region). The
   occupied-slot count is derived by scanning KEYSLOT_TABLE_STRIDE strides for the "VCKS" magic.
   Writes the 32-byte tag to out. Returns KAM_OK or KAM_ERR_IO. */
int KeyslotAreaMacCompute (KeyslotArea *area, uint64 regionLen,
                           const unsigned char kArea[32], unsigned char out[32]);

/* Compute + write the trailer at trailerOff. Returns KAM_OK or KAM_ERR_IO. */
int KeyslotAreaMacWrite (KeyslotArea *area, uint64 regionLen, uint64 trailerOff,
                         const unsigned char kArea[32]);

/* Read the trailer at trailerOff and verify it against a fresh computation. Returns KAM_OK (verified),
   KAM_TAMPERED (present but mismatched), KAM_NO_TRAILER (no magic: old area), or KAM_ERR_IO. */
int KeyslotAreaMacVerify (KeyslotArea *area, uint64 regionLen, uint64 trailerOff,
                          const unsigned char kArea[32]);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_KEYSLOT_AREA_MAC && VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_KeyslotAreaMac */
