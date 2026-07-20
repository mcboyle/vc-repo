/*
 * ShamirMac — keyed per-share authentication for Shamir shares (docs/VSS-SPEC.md, IDEAS-BACKLOG §D).
 *
 * Plain Shamir (Common/Shamir.c) and its CRC-32 secret checksum detect *accidental* corruption; a
 * keyed MAC is what detects an *adversarial* one. This module tags each share with
 * HMAC-SHA256(macKey, domain || x || len || y[]) so a share that was flipped, truncated, or
 * fabricated by an attacker is rejected before it ever enters shamir_combine — closing the
 * adversarial-share half of the "verifiable shares" item.
 *
 * Scope boundary (kept honest, see docs/VSS-SPEC.md): this authenticates each share against a key the
 * holders share; it does NOT prove the shares are mutually consistent (that a cheating *dealer* used
 * one polynomial). Dealer-consistency is Feldman/Pedersen VSS, which needs a prime-order group's
 * homomorphism (g^share == prod C_j^{i^j}) that GF(2^8) has no analogue for — proven separately as
 * the prime-field scheme in steps [31]/[32]. Split-key factor uses this MAC over the real GF(2^8)
 * shares; the two are complementary, not substitutes.
 *
 * Kept out of Shamir.c so that module stays standalone/dependency-free; this one links the in-tree
 * Crypto/Sha2.c. Gated -DVC_ENABLE_SHAMIR_MAC; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_ShamirMac
#define TC_HEADER_Common_ShamirMac

#include "Tcdefs.h"

#if defined(VC_ENABLE_SHAMIR_MAC)

#include "Shamir.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define SHAMIR_MAC_KEY_SIZE 32
#define SHAMIR_MAC_TAG_SIZE 32

/* Tag one share: tag = HMAC-SHA256(macKey, "VCSMshare1" || x || len || y[0..len)). */
void ShamirShareMac (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                     const ShamirShare *share, unsigned char tag[SHAMIR_MAC_TAG_SIZE]);

/* Verify a share's tag in constant time. Returns 1 on match, 0 otherwise. */
int  ShamirShareVerify (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                        const ShamirShare *share, const unsigned char tag[SHAMIR_MAC_TAG_SIZE]);

/* Convenience: MAC all 'count' shares (tags_out is count * SHAMIR_MAC_TAG_SIZE bytes). */
void ShamirMacAll (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                   const ShamirShare *shares, int count, unsigned char *tags_out);

/* Convenience: verify all 'count' shares against their tags. Returns 1 only if every share verifies
   (still checks every share — no early-out — so the result does not leak which share failed). */
int  ShamirVerifyAll (const unsigned char macKey[SHAMIR_MAC_KEY_SIZE],
                      const ShamirShare *shares, int count, const unsigned char *tags);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_SHAMIR_MAC */

#endif /* TC_HEADER_Common_ShamirMac */
