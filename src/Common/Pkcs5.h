/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_PKCS5
#define TC_HEADER_PKCS5

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifndef TC_WINDOWS_BOOT
/* output written to input_digest which must be at lease 32 bytes long */
void hmac_blake2s (unsigned char *key, int keylen, unsigned char *input_digest, int len);
void derive_key_blake2s (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* output written to d which must be at lease 32 bytes long */
void hmac_sha256 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha256 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* output written to d which must be at lease 64 bytes long */
void hmac_sha512 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha512 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* output written to d which must be at lease 64 bytes long */
void hmac_whirlpool (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_whirlpool (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

void hmac_streebog (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_streebog (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* HMAC-SHA3-512 PRF (FIPS 202). Output written to d/input_digest which must be at least 64 bytes long. */
void hmac_sha3_512 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha3_512 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

int get_pkcs5_iteration_count (int pkcs5_prf_id, int pim, BOOL bBoot, int* pMemoryCost);
wchar_t *get_kdf_name (int kdf_id);

#ifndef VC_DCS_DISABLE_ARGON2
int derive_key_argon2(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, uint32 memcost, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);
void get_argon2_params(int pim, int* pIterations, int* pMemcost);

#if defined(VC_ENABLE_ARGON2_PARAMS)
/*
 * Explicit Argon2id parameter override. Stock VeraCrypt shoehorns Argon2's memory/time cost into the
 * single PIM value (get_argon2_params) and fixes parallelism at 1. This lets the caller (the CLI) set
 * memory (KiB), iterations, and parallelism explicitly for the current process's create/mount, exactly
 * the way PIM is supplied: the values are NOT stored in the header, so the same three must be given at
 * mount as at create. See docs/ARGON2-PARAMS-SPEC.md. Gated; a build without it is byte-for-byte stock.
 */
void   Argon2SetParamsOverride (int active, uint32 memCostKiB, uint32 iterations, uint32 parallelism);
/* Resolve the effective (iterations, memCostKiB, parallelism) for a PIM: the override when active,
   else the stock PIM formula with parallelism 1. Returns 1 if the override was used, 0 otherwise. */
int    Argon2GetResolvedParams (int pim, uint32 *iterations, uint32 *memCostKiB, uint32 *parallelism);
/* Effective parallelism (override when active, else 1) — used at the argon2id_hash_raw call site. */
uint32 Argon2GetParallelism (void);
#endif

/* HMAC-BLAKE2b-512 PRF. Output written to d/input_digest which must be at least 64 bytes long.
   Gated with Argon2 as it reuses the BLAKE2b primitive that ships with Argon2. */
void hmac_blake2b (unsigned char *key, int keylen, unsigned char *input_digest, int len);
void derive_key_blake2b (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);
#endif

/* check if given PRF supported.*/
typedef enum
{
   PRF_BOOT_NO = 0,
   PRF_BOOT_MBR,
   PRF_BOOT_GPT
} PRF_BOOT_TYPE;

int is_pkcs5_prf_supported (int pkcs5_prf_id, PRF_BOOT_TYPE bootType);
#else // TC_WINDOWS_BOOT
/* output written to input_digest which must be at lease 32 bytes long */
void hmac_blake2s (unsigned char *key, int keylen, unsigned char *input_digest, int len);
void derive_key_blake2s (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen);

/* output written to d which must be at lease 32 bytes long */
void hmac_sha256 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha256 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen);

#endif

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_PKCS5
