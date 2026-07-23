/*
 * VolumeLabel — encrypted, deniable volume labels (ROI-TOP-50 item 43).
 *
 * A human-readable name ("work-laptop-backup") the owner can list, without leaking it to an examiner
 * who images the disk. VeraCrypt has no volume-name field on purpose (deniability); this keeps the
 * *name* private by storing it as an AEAD record that is indistinguishable from random without the
 * passphrase — reusing the exact keyslot record machinery (KeyslotWrap/KeyslotUnwrap), so no new
 * crypto primitive is introduced, only a payload framing:
 *
 *   plaintext[64] = "LBL1" || len[1] || label[len] || zero-pad        (fixed 64 bytes: length hidden)
 *   record[128]   = salt[32] || ct[64] || tag[32]                     (AEAD over the keyslot primitive)
 *
 * The fixed 64-byte plaintext means the label's *length* does not leak either. A wrong passphrase (or
 * a tampered record) fails the AEAD tag and yields no label. Gated behind VC_ENABLE_VOLUME_LABEL
 * (needs VC_ENABLE_KEYSLOTS for the AEAD); default build stays byte-for-byte stock.
 */
#ifndef TC_HEADER_Common_VolumeLabel
#define TC_HEADER_Common_VolumeLabel

#include "Tcdefs.h"

#if defined(VC_ENABLE_VOLUME_LABEL) && defined(VC_ENABLE_KEYSLOTS)

#include "Keyslot.h"   /* KeyslotKdfFn, KEYSLOT_SALT_SIZE, KEYSLOT_TAG_SIZE */

#if defined(__cplusplus)
extern "C" {
#endif

#define VOLUME_LABEL_MAX       48                       /* max UTF-8 bytes in a label */
#define VOLUME_LABEL_PT_SIZE   64                       /* fixed plaintext: "LBL1"||len||label||pad */
#define VOLUME_LABEL_MAGIC     "LBL1"
#define VOLUME_LABEL_RECORD_SIZE (KEYSLOT_SALT_SIZE + VOLUME_LABEL_PT_SIZE + KEYSLOT_TAG_SIZE) /* 128 */

/* ---- pure framing (no crypto) — the item's new logic, cross-checked byte-for-byte vs python ---- */

/* Build the fixed 64-byte plaintext for 'label' (labelLen 0..VOLUME_LABEL_MAX). Returns 0, or -1 if
   labelLen is out of range. 'out' must hold VOLUME_LABEL_PT_SIZE bytes. */
int VolumeLabelFrame (const char *label, int labelLen, unsigned char out[VOLUME_LABEL_PT_SIZE]);

/* Parse a 64-byte plaintext: verify the "LBL1" magic + a sane length, copy the label into buf (up to
   bufCap-1, NUL-terminated). Returns the label length, or -1 if the magic/length is invalid. */
int VolumeLabelParse (const unsigned char pt[VOLUME_LABEL_PT_SIZE], char *buf, int bufCap);

/* ---- passphrase-based set/get over the real keyslot AEAD ---- */

/* Frame 'label' and wrap it into a 128-byte record at 'out' under the passphrase (salt from randBytes).
   Returns 0 on success, -1 on a bad label length. */
int VolumeLabelSet (KeyslotKdfFn kdf, unsigned int cost,
                    const unsigned char *pass, int passLen,
                    const char *label, int labelLen,
                    void (*randBytes) (unsigned char *, size_t),
                    unsigned char out[VOLUME_LABEL_RECORD_SIZE]);

/* Unwrap the record with the passphrase and parse the label into buf. Returns the label length on
   success, or -1 if the passphrase is wrong, the record is tampered, or it is not a label record. */
int VolumeLabelGet (KeyslotKdfFn kdf, unsigned int cost,
                    const unsigned char *pass, int passLen,
                    const unsigned char rec[VOLUME_LABEL_RECORD_SIZE],
                    char *buf, int bufCap);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_VOLUME_LABEL && VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_VolumeLabel */
