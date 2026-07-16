/*
 * SHA-3 (Keccak) — FIPS 202, SHA3-512 variant.
 *
 * Portable public-domain implementation for VeraCrypt. The Keccak-f[1600]
 * permutation and sponge follow the reference specification; absorb/squeeze use
 * explicit little-endian lane arithmetic so the code is correct on both little-
 * and big-endian hosts (no reinterpretation of 64-bit lanes as raw bytes).
 *
 * SHA3-512: rate r = 72 bytes (576 bits), capacity c = 1024 bits, digest = 64 bytes.
 * The HMAC block size for SHA3-512 is the rate, i.e. 72 bytes.
 *
 * This implementation is dedicated to the public domain (CC0). It carries no
 * additional restrictions beyond those of the surrounding VeraCrypt distribution.
 */

#ifndef TC_HEADER_Crypto_Sha3
#define TC_HEADER_Crypto_Sha3

#include "Common/Tcdefs.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define SHA3_512_BLOCKSIZE   72   /* rate in bytes (HMAC block size)   */
#define SHA3_512_DIGESTSIZE  64   /* 512-bit output                    */

typedef struct SHA3_CTX_struct
{
	uint64 st[25];   /* 1600-bit Keccak state as 25 little-endian lanes */
	int pt;          /* current byte offset within the rate            */
	int rsiz;        /* rate in bytes                                  */
	int mdlen;       /* digest length in bytes                         */
} SHA3_CTX;

/* SHA3-512 streaming API (mirrors sha512_begin/hash/end and blake2s_init/update/final). */
void sha3_512_init (SHA3_CTX *ctx);
void sha3_512_update (SHA3_CTX *ctx, const unsigned char *in, size_t inlen);
void sha3_512_final (SHA3_CTX *ctx, unsigned char *md);  /* writes SHA3_512_DIGESTSIZE bytes */

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_Crypto_Sha3
