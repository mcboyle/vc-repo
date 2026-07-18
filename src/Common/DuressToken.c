/*
 * DuressToken — see DuressToken.h for the design.
 *
 * The tag is HMAC-SHA256(salt, passphrase). The hash primitive is VeraCrypt's own in-tree SHA-256
 * (Crypto/Sha2.c), so the "real compiled object" verification exercises the shipping hash; the small
 * standard HMAC ipad/opad wrapper is implemented here and proven byte-for-byte against an independent
 * HMAC-SHA256 in duress_reference.py.
 */

#include "DuressToken.h"

#if defined(VC_ENABLE_DURESS)

#include <string.h>
#include "Crypto/Sha2.h"     /* sha256_begin / sha256_hash / sha256_end */

#define DURESS_SHA256_BLOCK 64

static void duress_wipe (volatile unsigned char *p, int n)
{
	while (n--)
		*p++ = 0;
}

static void duress_hmac_sha256 (const unsigned char *key, int keyLen,
                                const unsigned char *msg, int msgLen,
                                unsigned char out[DURESS_TAG_SIZE])
{
	sha256_ctx    ctx;
	unsigned char k0[DURESS_SHA256_BLOCK];
	unsigned char pad[DURESS_SHA256_BLOCK];
	unsigned char inner[DURESS_TAG_SIZE];
	int i;

	/* K0: key padded to the block size (hashed first if longer than the block) */
	if (keyLen > DURESS_SHA256_BLOCK)
	{
		sha256_begin (&ctx);
		sha256_hash (key, (unsigned int) keyLen, &ctx);
		sha256_end (k0, &ctx);
		memset (k0 + DURESS_TAG_SIZE, 0, DURESS_SHA256_BLOCK - DURESS_TAG_SIZE);
	}
	else
	{
		if (keyLen > 0)
			memcpy (k0, key, keyLen);
		memset (k0 + keyLen, 0, DURESS_SHA256_BLOCK - keyLen);
	}

	/* inner = SHA256( (K0 ^ ipad) || msg ) */
	for (i = 0; i < DURESS_SHA256_BLOCK; i++)
		pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&ctx);
	sha256_hash (pad, DURESS_SHA256_BLOCK, &ctx);
	if (msgLen > 0)
		sha256_hash (msg, (unsigned int) msgLen, &ctx);
	sha256_end (inner, &ctx);

	/* out = SHA256( (K0 ^ opad) || inner ) */
	for (i = 0; i < DURESS_SHA256_BLOCK; i++)
		pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&ctx);
	sha256_hash (pad, DURESS_SHA256_BLOCK, &ctx);
	sha256_hash (inner, DURESS_TAG_SIZE, &ctx);
	sha256_end (out, &ctx);

	duress_wipe (k0, sizeof (k0));
	duress_wipe (pad, sizeof (pad));
	duress_wipe (inner, sizeof (inner));
	duress_wipe ((volatile unsigned char *) &ctx, sizeof (ctx));
}

void DuressTokenDerive (const unsigned char *salt, int saltLen,
                        const unsigned char *pass, int passLen,
                        unsigned char tagOut[DURESS_TAG_SIZE])
{
	if (passLen < 0)
		passLen = 0;
	if (passLen > DURESS_MAX_PASS)
		passLen = DURESS_MAX_PASS;
	duress_hmac_sha256 (salt, saltLen, pass, passLen, tagOut);
}

int DuressTokenMatch (const unsigned char *a, const unsigned char *b, int len)
{
	unsigned char diff = 0;
	int i;
	for (i = 0; i < len; i++)
		diff |= (unsigned char) (a[i] ^ b[i]);
	return diff == 0 ? 1 : 0;
}

int DuressTokenCheck (const unsigned char *salt, int saltLen,
                      const unsigned char *pass, int passLen,
                      const unsigned char expectedTag[DURESS_TAG_SIZE])
{
	unsigned char tag[DURESS_TAG_SIZE];
	int match;

	DuressTokenDerive (salt, saltLen, pass, passLen, tag);
	match = DuressTokenMatch (tag, expectedTag, DURESS_TAG_SIZE);
	duress_wipe (tag, sizeof (tag));
	return match;
}

#endif /* VC_ENABLE_DURESS */
