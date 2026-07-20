/*
 * ShareCode — a typo-detecting text encoding for a Shamir share, for the recovery kit
 * (docs/VSS-SPEC.md, IDEAS-BACKLOG §D "SLIP-39-style share encoding").
 *
 * SLIP-39's usability contribution is a checksummed, transcribable share format so a hand-copied
 * recovery share catches transcription errors instead of silently reconstructing garbage. This
 * provides that using a bech32 (BIP-173) BCH checksum — chosen over the full SLIP-39 standard because
 * SLIP-39 is a *separate* secret-sharing scheme with its own 1024-word list, which would duplicate
 * this project's GF(2^8) Shamir; the bech32 checksum gives the same typo-detection guarantee (any
 * <= 4 substitution errors detected while the string is <= 90 chars) with a self-contained,
 * standard-anchored construction.
 *
 * Encoding: "vcs1" || base32(ver || x || len || y[0..len) [|| mac[32]]) || 6-char bech32 checksum.
 * A single share of a 256-bit secret encodes to ~65 chars, well inside the 90-char guarantee window.
 *
 * Gated -DVC_ENABLE_SHARECODE; a build without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Common_ShareCode
#define TC_HEADER_Common_ShareCode

#include "Tcdefs.h"

#if defined(VC_ENABLE_SHARECODE)

#include "Shamir.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define SHARECODE_VERSION   1
#define SHARECODE_MAC_SIZE  32
/* worst case: "vcs1" + base32(ver+x+len + 64 y + 32 mac = 99 bytes -> 159 chars) + 6 + NUL */
#define SHARECODE_MAX_LEN   200

/* Result codes. */
#define SHARECODE_OK            0
#define SHARECODE_ERR_PARAM   (-1)
#define SHARECODE_ERR_CHECKSUM (-2)   /* bech32 checksum failed (a transcription error) */
#define SHARECODE_ERR_FORMAT  (-3)    /* not a well-formed vcs1... string */

/* Encode 'share' (and, if mac != NULL, its SHARECODE_MAC_SIZE-byte per-share MAC tag) into a
   NUL-terminated bech32 string in out[0..outCap). Returns SHARECODE_OK or a negative code. */
int ShareCodeEncode (const ShamirShare *share, const unsigned char *mac,
                     char *out, int outCap);

/* Decode a "vcs1..." string: verify the checksum, then fill *share and (if the string carried a MAC
   and macOut != NULL) macOut[0..32); *hasMac reports whether a MAC was present. Returns SHARECODE_OK,
   SHARECODE_ERR_CHECKSUM (transcription error — reject), or SHARECODE_ERR_FORMAT. */
int ShareCodeDecode (const char *str, ShamirShare *share,
                     unsigned char *macOut, int *hasMac);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_SHARECODE */

#endif /* TC_HEADER_Common_ShareCode */
