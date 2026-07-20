/*
 * ShamirMac — see ShamirMac.h. HMAC-SHA256 over the in-tree Crypto/Sha2.c, same construction as
 * the keyslot HMAC selector, domain-separated per share.
 */

#include "ShamirMac.h"

#if defined(VC_ENABLE_SHAMIR_MAC)

#include <string.h>
#include "Crypto/Sha2.h"

#define SM_BLK 64

static const unsigned char SM_DOMAIN[10] = { 'V','C','S','M','s','h','a','r','e','1' };

static void sm_wipe (volatile unsigned char *p, int n) { while (n--) *p++ = 0; }

/* HMAC-SHA256 over up to two message parts */
static void sm_hmac (const unsigned char *key, int keyLen,
                     const unsigned char *m1, int m1Len,
                     const unsigned char *m2, int m2Len,
                     unsigned char out[SHAMIR_MAC_TAG_SIZE])
{
	sha256_ctx ctx;
	unsigned char k0[SM_BLK], pad[SM_BLK], inner[SHAMIR_MAC_TAG_SIZE];
	int i;

	if (keyLen > SM_BLK)
	{
		sha256_begin (&ctx); sha256_hash (key, (unsigned int) keyLen, &ctx); sha256_end (k0, &ctx);
		memset (k0 + SHAMIR_MAC_TAG_SIZE, 0, SM_BLK - SHAMIR_MAC_TAG_SIZE);
	}
	else
	{
		if (keyLen > 0) memcpy (k0, key, keyLen);
		memset (k0 + keyLen, 0, SM_BLK - keyLen);
	}

	for (i = 0; i < SM_BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&ctx);
	sha256_hash (pad, SM_BLK, &ctx);
	if (m1Len > 0) sha256_hash (m1, (unsigned int) m1Len, &ctx);
	if (m2Len > 0) sha256_hash (m2, (unsigned int) m2Len, &ctx);
	sha256_end (inner, &ctx);

	for (i = 0; i < SM_BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&ctx);
	sha256_hash (pad, SM_BLK, &ctx);
	sha256_hash (inner, SHAMIR_MAC_TAG_SIZE, &ctx);
	sha256_end (out, &ctx);

	sm_wipe (k0, sizeof (k0)); sm_wipe (pad, sizeof (pad)); sm_wipe (inner, sizeof (inner));
	sm_wipe ((volatile unsigned char *) &ctx, sizeof (ctx));
}

void ShamirShareMac (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                     const ShamirShare *share, unsigned char tag[SHAMIR_MAC_TAG_SIZE])
{
	unsigned char hdr[10 + 1 + 1];
	int len = share->len;

	if (len < 0) len = 0;
	if (len > SHAMIR_MAX_SECRET) len = SHAMIR_MAX_SECRET;

	memcpy (hdr, SM_DOMAIN, sizeof (SM_DOMAIN));       /* domain || x || len */
	hdr[10] = share->x;
	hdr[11] = (unsigned char) len;
	sm_hmac (macKey, SHAMIR_MAC_KEY_SIZE, hdr, (int) sizeof (hdr), share->y, len, tag);
}

int ShamirShareVerify (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                       const ShamirShare *share, const unsigned char tag[SHAMIR_MAC_TAG_SIZE])
{
	unsigned char calc[SHAMIR_MAC_TAG_SIZE];
	unsigned char d = 0;
	int i;

	ShamirShareMac (macKey, share, calc);
	for (i = 0; i < SHAMIR_MAC_TAG_SIZE; i++)
		d |= (unsigned char) (calc[i] ^ tag[i]);
	sm_wipe (calc, sizeof (calc));
	return d == 0 ? 1 : 0;
}

void ShamirMacAll (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                   const ShamirShare *shares, int count, unsigned char *tags_out)
{
	int i;
	for (i = 0; i < count; i++)
		ShamirShareMac (macKey, &shares[i], tags_out + (size_t) i * SHAMIR_MAC_TAG_SIZE);
}

int ShamirVerifyAll (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                     const ShamirShare *shares, int count, const unsigned char *tags)
{
	int i, ok = 1;
	for (i = 0; i < count; i++)                        /* no early-out: fixed work, no which-share leak */
		ok &= ShamirShareVerify (macKey, &shares[i], tags + (size_t) i * SHAMIR_MAC_TAG_SIZE);
	return ok;
}

#endif /* VC_ENABLE_SHAMIR_MAC */
