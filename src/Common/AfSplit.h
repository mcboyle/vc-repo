/*
 * AfSplit — anti-forensic (AF) key-material splitting, LUKS/TKS1 style (docs/AF-SPLIT-SPEC.md).
 *
 * Diffuses key material across s stripes so that recovering it needs ALL of them: a partial remnant
 * (an SSD wear-leveling copy, a torn write) yields nothing. split fills s*n bytes from n; merge is
 * the inverse. The stripe randomness is caller-supplied (the store's CSPRNG hook), and the diffusion
 * hash is the in-tree Crypto/Sha2.c SHA-256, so this module links like Keyslot.c does.
 *
 * The algorithm is proven two ways in verification/afsplit_poc.c (build_and_verify.sh step [15]);
 * this shipping module generalizes it to arbitrary n (a trailing partial hash section, as in LUKS).
 * Gated with the keyslots feature it composes with; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_AfSplit
#define TC_HEADER_Common_AfSplit

#include "Tcdefs.h"

#if defined(VC_ENABLE_KEYSLOTS)

#if defined(__cplusplus)
extern "C" {
#endif

/* Split 'material' (n bytes) into s stripes written to 'stripes' (s*n bytes). Stripes 0..s-2 are
   filled from 'rng'; the last stripe binds them to the material through the diffusion chain.
   s == 1 degenerates to a plain copy (no split). Returns 0 on success, -1 on bad parameters. */
int AfSplit (const unsigned char *material, int n, int s,
             void (*rng) (unsigned char *, size_t),
             unsigned char *stripes);

/* Recover the n-byte material from 'stripes' (s*n bytes, as produced by AfSplit). Any modified or
   missing stripe yields garbage (that is the point); callers authenticate the result separately. */
void AfMerge (const unsigned char *stripes, int n, int s, unsigned char *materialOut);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_KEYSLOTS */

#endif /* TC_HEADER_Common_AfSplit */
