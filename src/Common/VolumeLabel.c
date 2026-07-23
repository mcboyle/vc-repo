/*
 * VolumeLabel — see VolumeLabel.h. Payload framing + AEAD via the keyslot primitive (no new crypto).
 */
#include "VolumeLabel.h"

#if defined(VC_ENABLE_VOLUME_LABEL) && defined(VC_ENABLE_KEYSLOTS)

#include <string.h>

/* record layout offsets */
#define VL_SALT 0
#define VL_CT   (KEYSLOT_SALT_SIZE)
#define VL_TAG  (KEYSLOT_SALT_SIZE + VOLUME_LABEL_PT_SIZE)

/* AAD domain-separates a label record from a VMK keyslot record even under the same passphrase. */
static const unsigned char VL_AAD[9] = { 'V','C','K','S','l','a','b','e','l' };

int VolumeLabelFrame (const char *label, int labelLen, unsigned char out[VOLUME_LABEL_PT_SIZE])
{
	if (labelLen < 0 || labelLen > VOLUME_LABEL_MAX) return -1;
	memset (out, 0, VOLUME_LABEL_PT_SIZE);
	memcpy (out, VOLUME_LABEL_MAGIC, 4);
	out[4] = (unsigned char) labelLen;
	if (labelLen > 0) memcpy (out + 5, label, (size_t) labelLen);
	return 0;
}

int VolumeLabelParse (const unsigned char pt[VOLUME_LABEL_PT_SIZE], char *buf, int bufCap)
{
	int len;
	if (memcmp (pt, VOLUME_LABEL_MAGIC, 4) != 0) return -1;
	len = pt[4];
	if (len > VOLUME_LABEL_MAX || 5 + len > VOLUME_LABEL_PT_SIZE) return -1;
	if (buf && bufCap > 0) {
		int n = (len < bufCap - 1) ? len : bufCap - 1;
		if (n > 0) memcpy (buf, pt + 5, (size_t) n);
		buf[n] = '\0';
	}
	return len;
}

int VolumeLabelSet (KeyslotKdfFn kdf, unsigned int cost,
                    const unsigned char *pass, int passLen,
                    const char *label, int labelLen,
                    void (*randBytes) (unsigned char *, size_t),
                    unsigned char out[VOLUME_LABEL_RECORD_SIZE])
{
	unsigned char pt[VOLUME_LABEL_PT_SIZE], salt[KEYSLOT_SALT_SIZE];
	if (VolumeLabelFrame (label, labelLen, pt) != 0) return -1;
	randBytes (salt, sizeof salt);
	memcpy (out + VL_SALT, salt, KEYSLOT_SALT_SIZE);
	KeyslotWrap (kdf, cost, pass, passLen, salt, KEYSLOT_SALT_SIZE,
	             VL_AAD, (int) sizeof VL_AAD, pt, VOLUME_LABEL_PT_SIZE,
	             out + VL_CT, out + VL_TAG);
	memset (pt, 0, sizeof pt);
	return 0;
}

int VolumeLabelGet (KeyslotKdfFn kdf, unsigned int cost,
                    const unsigned char *pass, int passLen,
                    const unsigned char rec[VOLUME_LABEL_RECORD_SIZE],
                    char *buf, int bufCap)
{
	unsigned char pt[VOLUME_LABEL_PT_SIZE];
	int len;
	if (!KeyslotUnwrap (kdf, cost, pass, passLen, rec + VL_SALT, KEYSLOT_SALT_SIZE,
	                    VL_AAD, (int) sizeof VL_AAD, rec + VL_CT, VOLUME_LABEL_PT_SIZE,
	                    rec + VL_TAG, pt))
	{
		memset (pt, 0, sizeof pt);
		return -1;                                  /* wrong passphrase or tampered record */
	}
	len = VolumeLabelParse (pt, buf, bufCap);
	memset (pt, 0, sizeof pt);
	return len;                                     /* -1 if unwrapped but not a label record */
}

#endif /* VC_ENABLE_VOLUME_LABEL && VC_ENABLE_KEYSLOTS */
