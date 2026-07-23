/*
 * HeaderBackup — see HeaderBackup.h. Integrity-checked keyslot-area backup/restore.
 */
#include "HeaderBackup.h"

#if defined(VC_ENABLE_HEADER_BACKUP)

#include <string.h>
#include "Crypto/Sha2.h"

static const unsigned char HB_MAGIC[8] = { 'V','C','H','D','R','B','K','1' };
#define HB_VER 1

static void put_u64_be (unsigned char *p, uint64 v)
{ int i; for (i = 7; i >= 0; i--) { p[i] = (unsigned char)(v & 0xff); v >>= 8; } }
static uint64 get_u64_be (const unsigned char *p)
{ uint64 v = 0; int i; for (i = 0; i < 8; i++) v = (v << 8) | p[i]; return v; }

/* offsets within the blob */
#define O_MAGIC 0
#define O_VER   8
#define O_LEN   9
#define O_AREA  17

int HeaderBackupCreate (KeyslotArea *area, unsigned char *out, size_t outCap, size_t *outLen)
{
	uint64 sz = area->size (area->ctx);
	size_t total = (size_t) sz + HEADER_BACKUP_OVERHEAD;
	if (outCap < total)
		return HB_ERR_SPACE;
	memcpy (out + O_MAGIC, HB_MAGIC, 8);
	out[O_VER] = HB_VER;
	put_u64_be (out + O_LEN, sz);
	if (area->read (area->ctx, 0, out + O_AREA, (size_t) sz) != 0)
		return HB_ERR_IO;
	sha256 (out + O_AREA + sz, out, (unsigned int) (O_AREA + sz));   /* tag over everything before it */
	if (outLen) *outLen = total;
	return HB_OK;
}

int HeaderBackupVerify (const unsigned char *blob, size_t len)
{
	uint64 areaLen;
	unsigned char tag[32];
	if (len < HEADER_BACKUP_OVERHEAD)                    return HB_ERR_FORMAT;
	if (memcmp (blob + O_MAGIC, HB_MAGIC, 8) != 0)       return HB_ERR_FORMAT;
	if (blob[O_VER] != HB_VER)                           return HB_ERR_FORMAT;
	areaLen = get_u64_be (blob + O_LEN);
	if ((uint64) len != (uint64) O_AREA + areaLen + 32)  return HB_ERR_FORMAT;
	sha256 (tag, blob, (unsigned int) (O_AREA + areaLen));
	if (memcmp (tag, blob + O_AREA + areaLen, 32) != 0)  return HB_ERR_INTEGRITY;
	return HB_OK;
}

int HeaderBackupRestore (const unsigned char *blob, size_t len, KeyslotArea *area)
{
	int rc = HeaderBackupVerify (blob, len);
	uint64 areaLen;
	if (rc != HB_OK)
		return rc;                                       /* never restore an unverified/corrupt blob */
	areaLen = get_u64_be (blob + O_LEN);
	if (areaLen > area->size (area->ctx))
		return HB_ERR_SPACE;
	if (area->write (area->ctx, 0, blob + O_AREA, (size_t) areaLen) != 0)
		return HB_ERR_IO;
	return HB_OK;
}

#endif /* VC_ENABLE_HEADER_BACKUP */
