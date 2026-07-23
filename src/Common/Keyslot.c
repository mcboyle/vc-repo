/*
 * Keyslot — see Keyslot.h. The hash primitive is the in-tree Crypto/Sha2.c (SHA-256, for HMAC) and
 * the wrap cipher is Crypto/chacha256.c (ChaCha20); both are real shipping objects. The KDF is
 * supplied by the caller (KeyslotKdfFn), so this module links without the KDF's dependencies.
 */

#include "Keyslot.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include <string.h>
#include "Crypto/Sha2.h"
#include "Crypto/chacha256.h"

#define KS_SHA256_BLK 64

static void ks_wipe (volatile unsigned char *p, int n) { while (n--) *p++ = 0; }

static void ks_hmac_sha256 (const unsigned char *key, int keyLen,
                            const unsigned char *m1, int m1Len,
                            const unsigned char *m2, int m2Len,
                            unsigned char out[KEYSLOT_TAG_SIZE])
{
	sha256_ctx ctx;
	unsigned char k0[KS_SHA256_BLK], pad[KS_SHA256_BLK], inner[KEYSLOT_TAG_SIZE];
	int i;

	if (keyLen > KS_SHA256_BLK)
	{
		sha256_begin (&ctx); sha256_hash (key, (unsigned int) keyLen, &ctx); sha256_end (k0, &ctx);
		memset (k0 + KEYSLOT_TAG_SIZE, 0, KS_SHA256_BLK - KEYSLOT_TAG_SIZE);
	}
	else
	{
		if (keyLen > 0) memcpy (k0, key, keyLen);
		memset (k0 + keyLen, 0, KS_SHA256_BLK - keyLen);
	}

	for (i = 0; i < KS_SHA256_BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x36);
	sha256_begin (&ctx);
	sha256_hash (pad, KS_SHA256_BLK, &ctx);
	if (m1Len > 0) sha256_hash (m1, (unsigned int) m1Len, &ctx);
	if (m2Len > 0) sha256_hash (m2, (unsigned int) m2Len, &ctx);
	sha256_end (inner, &ctx);

	for (i = 0; i < KS_SHA256_BLK; i++) pad[i] = (unsigned char) (k0[i] ^ 0x5c);
	sha256_begin (&ctx);
	sha256_hash (pad, KS_SHA256_BLK, &ctx);
	sha256_hash (inner, KEYSLOT_TAG_SIZE, &ctx);
	sha256_end (out, &ctx);

	ks_wipe (k0, sizeof (k0)); ks_wipe (pad, sizeof (pad)); ks_wipe (inner, sizeof (inner));
	ks_wipe ((volatile unsigned char *) &ctx, sizeof (ctx));
}

int KeyslotConstTimeEqual (const unsigned char *a, const unsigned char *b, int len)
{
	unsigned char d = 0;
	int i;
	for (i = 0; i < len; i++)
		d |= (unsigned char) (a[i] ^ b[i]);
	return d == 0 ? 1 : 0;
}

void KeyslotWrapWithDK (const unsigned char dk[KEYSLOT_DK_SIZE],
                        const unsigned char *aad, int aadLen,
                        const unsigned char *vmk, int vmkLen,
                        unsigned char *ctOut, unsigned char tagOut[KEYSLOT_TAG_SIZE])
{
	ChaCha256Ctx cc;
	ChaCha256Init (&cc, dk, dk + 32, 20);                /* encKey=dk[0..32), iv=dk[32..40), ChaCha20 */
	ChaCha256Encrypt (&cc, vmk, (size_t) vmkLen, ctOut);
	ks_hmac_sha256 (dk + 40, 32, aad, aadLen, ctOut, vmkLen, tagOut);
	ks_wipe ((volatile unsigned char *) &cc, sizeof (cc));
}

int KeyslotUnwrapWithDK (const unsigned char dk[KEYSLOT_DK_SIZE],
                         const unsigned char *aad, int aadLen,
                         const unsigned char *ct, int ctLen,
                         const unsigned char tag[KEYSLOT_TAG_SIZE],
                         unsigned char *vmkOut)
{
	ChaCha256Ctx cc;
	unsigned char calc[KEYSLOT_TAG_SIZE];
	int ok;

	ks_hmac_sha256 (dk + 40, 32, aad, aadLen, ct, ctLen, calc);
	ok = KeyslotConstTimeEqual (calc, tag, KEYSLOT_TAG_SIZE);
	if (ok)
	{
		ChaCha256Init (&cc, dk, dk + 32, 20);
		ChaCha256Encrypt (&cc, ct, (size_t) ctLen, vmkOut);   /* stream cipher: decrypt == encrypt */
		ks_wipe ((volatile unsigned char *) &cc, sizeof (cc));
	}
	ks_wipe (calc, sizeof (calc));
	return ok;
}

int KeyslotUnwrapCT (KeyslotKdfFn kdf, unsigned int cost,
                     const unsigned char *pass, int passLen,
                     const unsigned char *salt, int saltLen,
                     const unsigned char *aad, int aadLen,
                     const unsigned char *ct, int ctLen,
                     const unsigned char tag[KEYSLOT_TAG_SIZE],
                     unsigned char *vmkOut)
{
	unsigned char dk[KEYSLOT_DK_SIZE], calc[KEYSLOT_TAG_SIZE];
	ChaCha256Ctx cc;
	int ok;

	kdf (pass, passLen, salt, saltLen, cost, dk, KEYSLOT_DK_SIZE);
	ks_hmac_sha256 (dk + 40, 32, aad, aadLen, ct, ctLen, calc);
	ok = KeyslotConstTimeEqual (calc, tag, KEYSLOT_TAG_SIZE);
	/* decrypt unconditionally so timing is identical for matching and non-matching slots */
	ChaCha256Init    (&cc, dk, dk + 32, 20);
	ChaCha256Encrypt (&cc, ct, (size_t) ctLen, vmkOut);

	ks_wipe (dk, sizeof (dk));
	ks_wipe (calc, sizeof (calc));
	ks_wipe ((volatile unsigned char *) &cc, sizeof (cc));
	return ok;
}

void KeyslotWrap (KeyslotKdfFn kdf, unsigned int cost,
                  const unsigned char *pass, int passLen,
                  const unsigned char *salt, int saltLen,
                  const unsigned char *aad, int aadLen,
                  const unsigned char *vmk, int vmkLen,
                  unsigned char *ctOut, unsigned char tagOut[KEYSLOT_TAG_SIZE])
{
	unsigned char dk[KEYSLOT_DK_SIZE];
	kdf (pass, passLen, salt, saltLen, cost, dk, KEYSLOT_DK_SIZE);
	KeyslotWrapWithDK (dk, aad, aadLen, vmk, vmkLen, ctOut, tagOut);
	ks_wipe (dk, sizeof (dk));
}

int KeyslotUnwrap (KeyslotKdfFn kdf, unsigned int cost,
                   const unsigned char *pass, int passLen,
                   const unsigned char *salt, int saltLen,
                   const unsigned char *aad, int aadLen,
                   const unsigned char *ct, int ctLen,
                   const unsigned char tag[KEYSLOT_TAG_SIZE],
                   unsigned char *vmkOut)
{
	unsigned char dk[KEYSLOT_DK_SIZE];
	int ok;
	kdf (pass, passLen, salt, saltLen, cost, dk, KEYSLOT_DK_SIZE);
	ok = KeyslotUnwrapWithDK (dk, aad, aadLen, ct, ctLen, tag, vmkOut);
	ks_wipe (dk, sizeof (dk));
	return ok;
}

#endif /* VC_ENABLE_KEYSLOTS */
