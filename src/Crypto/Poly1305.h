/*
 * Poly1305 one-shot MAC (RFC 8439) — shippable form of the proven verification PoC
 * (verification/poly1305_poc.c, suite step [18]: RFC 8439 §2.5.2 KATs + an independent
 * python bigint reference). Gated VC_ENABLE_POLY1305; default builds are byte-for-byte stock.
 *
 * Consumed by the Adiantum wide-block mode (src/Crypto/Adiantum.c) as the polynomial term of its
 * epsilon-almost-Delta-universal hash: called with a key r||0^16 the trailing +s adds nothing, so
 * the 16-byte output is exactly the hash value mod 2^128 (see docs/ADIANTUM-SPEC.md).
 *
 * Constant-time in the classic radix-2^26 "donna" style: no secret-dependent branch or memory index
 * (the final conditional subtraction is a masked select). Not a from-scratch bignum — the proven
 * reduction schedule, matched against the RFC KATs.
 */

#ifndef TC_HEADER_Crypto_Poly1305
#define TC_HEADER_Crypto_Poly1305

#if defined(VC_ENABLE_POLY1305)

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute the 16-byte Poly1305 tag over msg[0..len) with the 32-byte one-time key. */
void Poly1305 (unsigned char out[16], const unsigned char *msg, size_t len, const unsigned char key[32]);

#ifdef __cplusplus
}
#endif

#endif /* VC_ENABLE_POLY1305 */
#endif /* TC_HEADER_Crypto_Poly1305 */
