/*
 * HeaderBackup — integrity-checked backup/restore of a keyslot area (ROI-TOP-50 item 44).
 *
 * A corrupted or torn header/keyslot area can brick a volume. This makes a self-describing backup blob
 * with a SHA-256 integrity tag, so a backup can be VERIFIED before it is trusted and a corrupted area
 * detected and restored from a good copy. Operates over the abstract KeyslotArea, so it works for the
 * header-slack, sidecar, or a test buffer. Gated behind VC_ENABLE_HEADER_BACKUP.
 *
 * Blob layout:  magic[8]="VCHDRBK1" || ver[1]=1 || areaLen[8 big-endian] || area[areaLen] || sha256[32]
 *   sha256 = SHA-256(magic || ver || areaLen || area)   — covers everything before the tag.
 */
#ifndef TC_HEADER_Common_HeaderBackup
#define TC_HEADER_Common_HeaderBackup

#include "Tcdefs.h"

/* Operates over the keyslot machinery's KeyslotArea, so it needs VC_ENABLE_KEYSLOTS too
 * (the KeyslotArea type is itself gated behind it). A HEADER_BACKUP-only build is a no-op. */
#if defined(VC_ENABLE_HEADER_BACKUP) && defined(VC_ENABLE_KEYSLOTS)

#include "KeyslotStore.h"   /* KeyslotArea */
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define HEADER_BACKUP_OVERHEAD (8 + 1 + 8 + 32)   /* magic+ver+len+tag around the area bytes */

/* Result codes. */
#define HB_OK           0
#define HB_ERR_FORMAT (-1)   /* bad magic / version / length                 */
#define HB_ERR_INTEGRITY (-2)/* SHA-256 tag mismatch (corruption/tamper)      */
#define HB_ERR_IO      (-3)   /* area read/write failed                       */
#define HB_ERR_SPACE   (-4)   /* output buffer too small                      */

/* Serialise the whole area into 'out' (needs area size + HEADER_BACKUP_OVERHEAD). *outLen is set. */
int HeaderBackupCreate  (KeyslotArea *area, unsigned char *out, size_t outCap, size_t *outLen);
/* Verify a backup blob's format + integrity tag WITHOUT writing anything. */
int HeaderBackupVerify  (const unsigned char *blob, size_t len);
/* Verify then write the area bytes back over 'area'. Refuses to restore a blob that fails verification. */
int HeaderBackupRestore (const unsigned char *blob, size_t len, KeyslotArea *area);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_HEADER_BACKUP && VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_HeaderBackup */
