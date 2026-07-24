/*
 * Adiantum wide-block encryption mode (XChaCha12 / AES-256 / NH+Poly1305) — shippable form of the proven
 * verification PoC (verification/adiantum_poc.c, suite step [24]: all official google/adiantum KATs, and
 * step [89]: the same KATs with the constant-time AES substituted). Gated VC_ENABLE_ADIANTUM; default
 * builds are byte-for-byte stock.
 *
 * Adiantum encrypts a whole sector as ONE block: flipping any ciphertext bit scrambles the entire sector
 * on decrypt, closing the 16-byte-granular malleability XTS leaves open (docs/ADIANTUM-SPEC.md, D-4). It
 * is the non-AES-NI wide-block companion to the per-sector MAC work — malleability-hardening, NOT
 * authentication (a MAC still detects tampering; Adiantum only amplifies it).
 *
 * Dependencies are the real in-tree primitives: the AES-256 block runs through the constant-time
 * src/Crypto/AesCt (VC_ENABLE_CTAES) — one block per sector, so a table-free AES is affordable and closes
 * the cache-timing leak (docs/CT-AES-SPEC.md); the bulk XChaCha12 stream runs through src/Crypto/chacha256;
 * the polynomial hash runs through src/Crypto/Poly1305 (VC_ENABLE_POLY1305). HChaCha12, NH and the 128-bit
 * add/sub are Adiantum-specific and local to Adiantum.c.
 *
 * VC_ENABLE_ADIANTUM implies VC_ENABLE_CTAES and VC_ENABLE_POLY1305 (make ADIANTUM=1 sets all three).
 */

#ifndef TC_HEADER_Crypto_Adiantum
#define TC_HEADER_Crypto_Adiantum

#if defined(VC_ENABLE_ADIANTUM)

#include <stddef.h>
#include "Crypto/AesCt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADIANTUM_MAX_SECTOR  4096      /* largest sector this build supports */
#define ADIANTUM_MAX_TWEAK   64        /* largest tweak (sector index / associated data) */

typedef struct AdiantumKey_t
{
	unsigned char k[32];               /* outer key: bulk XChaCha12 stream key */
	unsigned char rt[16], rm[16];      /* Poly1305 keys for the tweak- and message-hash terms */
	unsigned char kn[1072];            /* NH key: 268 little-endian u32 words */
	AesCtKey256   blk;                 /* constant-time AES-256: one expanded key, both directions */
} AdiantumKey;

/* Expand a 256-bit key into the Adiantum subkeys (constant-time block schedule). */
void AdiantumInit (AdiantumKey *ak, const unsigned char key[32]);

/* Wide-block encrypt/decrypt one sector. len must be in [16, ADIANTUM_MAX_SECTOR]; tlen <= ADIANTUM_MAX_TWEAK.
   `in` and `out` are len bytes and may alias (in == out is supported). Returns 1 on success, 0 if the
   length/tweak bounds are violated (output untouched). */
int AdiantumEncrypt (const AdiantumKey *ak, const unsigned char *tweak, size_t tlen,
                     const unsigned char *pt, size_t len, unsigned char *ct);
int AdiantumDecrypt (const AdiantumKey *ak, const unsigned char *tweak, size_t tlen,
                     const unsigned char *ct, size_t len, unsigned char *pt);

#ifdef __cplusplus
}
#endif

#endif /* VC_ENABLE_ADIANTUM */
#endif /* TC_HEADER_Crypto_Adiantum */
