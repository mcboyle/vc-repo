/*
 * AesCt — constant-time AES-256 (research T2-3/T2-4), gated VC_ENABLE_CTAES; default builds are stock.
 *
 * The Adiantum wide-block mode invokes AES-256 on ONE 16-byte block per sector on non-AES-NI hardware
 * (docs/ADIANTUM-SPEC.md, D-4). That call must be constant-time — a table-based AES leaks the key through
 * cache timing (measured LEAKY, docs/CT-HARDENING-R17.md) — but need NOT be fast (once per sector, A-2).
 *
 * This is the shippable form of the proven verification PoC (verification/ctaes_poc.c, suite step [87]):
 * the S-box is computed as  S(x) = affine( x^{-1} in GF(2^8) )  with branchless, table-free GF(2^8)
 * arithmetic (the same construction proven constant-time in Shamir.c — dudect + ctgrind clean, step [41]).
 * ShiftRows is a fixed permutation, MixColumns uses a masked branch-free xtime, AddRoundKey is XOR and the
 * key schedule reuses the same S-box, so there is NO secret-dependent branch or memory index anywhere.
 *
 * API mirrors the "expand the key once, encrypt one block per sector" usage the wide-block modes need.
 * Encrypt-only (Adiantum/HCTR2 use AES in the forward direction for their block operations). A faster
 * bitsliced S-box can replace the inner inverse later behind this same interface without changing callers.
 */

#ifndef TC_HEADER_Crypto_AesCt
#define TC_HEADER_Crypto_AesCt

#if defined(VC_ENABLE_CTAES)

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AESCT_ROUNDS_256   14
#define AESCT_RK_BYTES     (16 * (AESCT_ROUNDS_256 + 1))   /* 240-byte expanded key schedule */

typedef struct { unsigned char rk[AESCT_RK_BYTES]; } AesCtKey256;

/* Expand a 256-bit key into the round-key schedule (constant-time). */
void AesCtInit256 (AesCtKey256 *ctx, const unsigned char key[32]);

/* Encrypt one 16-byte block under the expanded key (constant-time). in and out may alias. */
void AesCtEncryptBlock (const AesCtKey256 *ctx, const unsigned char in[16], unsigned char out[16]);

/* One-shot convenience: expand `key` and encrypt a single block. */
void AesCtEncrypt256 (const unsigned char key[32], const unsigned char in[16], unsigned char out[16]);

#ifdef __cplusplus
}
#endif

#endif /* VC_ENABLE_CTAES */
#endif /* TC_HEADER_Crypto_AesCt */
