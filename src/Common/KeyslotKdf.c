/*
 * KeyslotKdf — the product KDF binding for keyslots.
 *
 * Keyslot.{c,h} is KDF-agnostic (it takes a KeyslotKdfFn) so it links without the KDF's dependencies
 * and so the verification harness can drive it with a linkable PBKDF2-HMAC-SHA256. This file supplies
 * the *shipping* binding: VeraCrypt's own in-tree derive_key_sha512 (PBKDF2-HMAC-SHA512), the same KDF
 * the product already trusts. It is kept in its own translation unit so only it pulls Common/Pkcs5.
 *
 * Gated behind -DVC_ENABLE_KEYSLOTS; a build without it is byte-for-byte stock.
 */

#include "Keyslot.h"

#if defined(VC_ENABLE_KEYSLOTS)

#include <stddef.h>       /* wchar_t, referenced by Pkcs5.h declarations */
#include "Pkcs5.h"        /* derive_key_sha512 */

/* KeyslotKdfFn binding: 'cost' is the PBKDF2 iteration count. */
void KeyslotKdfSha512 (const unsigned char *pass, int passLen,
                       const unsigned char *salt, int saltLen,
                       unsigned int cost, unsigned char *dkOut, int dkLen)
{
	derive_key_sha512 (pass, passLen, salt, saltLen, (uint32) cost, dkOut, dkLen, NULL);
}

#endif /* VC_ENABLE_KEYSLOTS */
