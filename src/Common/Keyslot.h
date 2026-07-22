/*
 * Keyslot — per-slot authenticated wrapping of the volume master key (VMK).
 *
 * Multiple keyslots let a volume be opened by any of several independent passphrases/factors without
 * re-encrypting the body: the VMK is fixed, and each slot stores it wrapped under a key derived from
 * that slot's passphrase. Slot 0 is the untouched native VeraCrypt header; slots 1..N are these
 * records, placed by one of the KeyslotStore backends (in-header table / deniable free-space /
 * sidecar). See docs/KEYSLOTS-SPEC.md. This is a deliberately fork-only format, gated behind
 * -DVC_ENABLE_KEYSLOTS; a build without it is byte-for-byte stock.
 *
 * The wrapping construction (proven two ways in verification/keyslot_poc.c):
 *     dk     = KDF(passphrase, salt, cost, 72 bytes)         # pluggable; product: derive_key_sha512
 *     encKey = dk[0..32)  iv = dk[32..40)  macKey = dk[40..72)
 *     ct     = ChaCha20(encKey, iv) XOR vmk
 *     tag    = HMAC-SHA256(macKey, aad || ct)                # aad authenticates the slot header + salt
 * Opening recomputes dk, recomputes the tag, constant-time-compares it (this doubles as "does this
 * passphrase own this slot?"), and only then decrypts ct back to the VMK.
 *
 * This module is KDF-agnostic (the caller passes a KeyslotKdfFn) so it links without pulling the KDF's
 * dependencies; the crypto that is new here — the ChaCha wrap + HMAC selector — is what the harness
 * proves, while the KDF is an already-proven in-tree primitive.
 */

#ifndef TC_HEADER_Common_Keyslot
#define TC_HEADER_Common_Keyslot

#include "Tcdefs.h"

#if defined(VC_ENABLE_KEYSLOTS)

#if defined(__cplusplus)
extern "C" {
#endif

#define KEYSLOT_SALT_SIZE 32
#define KEYSLOT_TAG_SIZE  32
#define KEYSLOT_DK_SIZE   72    /* 32 encKey + 8 iv + 32 macKey */
#define KEYSLOT_VMK_MAX   512   /* max wrapped payload (a VeraCrypt header plaintext fits) */

/* slot flags */
#define KEYSLOT_FLAG_DURESS   0x01   /* opening this slot means "run the safe duress action", not mount */
#define KEYSLOT_FLAG_READONLY 0x02   /* (VC_ENABLE_KEYSLOT_POLICY) this slot may only mount read-only */

/* Derive KEYSLOT_DK_SIZE bytes from a passphrase+salt. 'cost' is KDF-specific (PBKDF2 iterations or
   an Argon2 parameter index). The product binds this to the in-tree derive_key_sha512. */
typedef void (*KeyslotKdfFn) (const unsigned char *pass, int passLen,
                              const unsigned char *salt, int saltLen,
                              unsigned int cost, unsigned char *dkOut, int dkLen);

/* ---- pure wrap/unwrap given an already-derived key (no KDF) ---- */

void KeyslotWrapWithDK   (const unsigned char dk[KEYSLOT_DK_SIZE],
                          const unsigned char *aad, int aadLen,
                          const unsigned char *vmk, int vmkLen,
                          unsigned char *ctOut, unsigned char tagOut[KEYSLOT_TAG_SIZE]);

/* returns 1 and fills vmkOut (== ctLen bytes) if the tag matches, 0 otherwise */
int  KeyslotUnwrapWithDK (const unsigned char dk[KEYSLOT_DK_SIZE],
                          const unsigned char *aad, int aadLen,
                          const unsigned char *ct, int ctLen,
                          const unsigned char tag[KEYSLOT_TAG_SIZE],
                          unsigned char *vmkOut);

/* Constant-time unwrap for scanning multiple slots: ALWAYS derives the key, ALWAYS computes the MAC,
   and ALWAYS decrypts into vmkOut (even on a non-match, so the per-slot work and timing do not reveal
   which slot matched or how many are populated). Returns 1 on match, 0 otherwise, via a constant-time
   comparison. vmkOut holds ctLen bytes either way (garbage on a non-match — the caller selects in
   constant time). */
int  KeyslotUnwrapCT (KeyslotKdfFn kdf, unsigned int cost,
                      const unsigned char *pass, int passLen,
                      const unsigned char *salt, int saltLen,
                      const unsigned char *aad, int aadLen,
                      const unsigned char *ct, int ctLen,
                      const unsigned char tag[KEYSLOT_TAG_SIZE],
                      unsigned char *vmkOut);

/* ---- passphrase-based wrap/unwrap (derive dk via kdf, then the above) ---- */

void KeyslotWrap   (KeyslotKdfFn kdf, unsigned int cost,
                    const unsigned char *pass, int passLen,
                    const unsigned char *salt, int saltLen,
                    const unsigned char *aad, int aadLen,
                    const unsigned char *vmk, int vmkLen,
                    unsigned char *ctOut, unsigned char tagOut[KEYSLOT_TAG_SIZE]);

int  KeyslotUnwrap (KeyslotKdfFn kdf, unsigned int cost,
                    const unsigned char *pass, int passLen,
                    const unsigned char *salt, int saltLen,
                    const unsigned char *aad, int aadLen,
                    const unsigned char *ct, int ctLen,
                    const unsigned char tag[KEYSLOT_TAG_SIZE],
                    unsigned char *vmkOut);

/* constant-time equality (exposed for the store's tag/marker checks) */
int  KeyslotConstTimeEqual (const unsigned char *a, const unsigned char *b, int len);

/* Shipping KeyslotKdfFn binding (Common/KeyslotKdf.c): VeraCrypt's in-tree derive_key_sha512
   (PBKDF2-HMAC-SHA512); 'cost' is the iteration count. Kept in its own TU so only it pulls Pkcs5. */
void KeyslotKdfSha512 (const unsigned char *pass, int passLen,
                       const unsigned char *salt, int saltLen,
                       unsigned int cost, unsigned char *dkOut, int dkLen);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_Keyslot */
