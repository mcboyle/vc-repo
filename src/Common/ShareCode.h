/*
 * ShareCode — a typo-detecting text encoding for a Shamir share, for the recovery kit
 * (docs/VSS-SPEC.md, IDEAS-BACKLOG §D "SLIP-39-style share encoding").
 *
 * SLIP-39's usability contribution is a checksummed, transcribable share format so a hand-copied
 * recovery share catches transcription errors instead of silently reconstructing garbage. This
 * provides that using a bech32m (BIP-350) BCH checksum — chosen over the full SLIP-39 standard because
 * SLIP-39 is a *separate* secret-sharing scheme with its own 1024-word list, which would duplicate
 * this project's GF(2^8) Shamir; the bech32m checksum gives the same typo-detection guarantee (any
 * <= 4 substitution errors detected while the string is <= 89 chars) with a self-contained,
 * standard-anchored construction. bech32m (constant 0x2bc830a3) supersedes plain bech32 (BIP-173,
 * constant 1) here per decision D-2: bech32's constant-1 leaves a residual insertion/deletion weakness
 * that BIP-350 was published to remove (see docs/VSS-SPEC.md). For the richer default export — longer
 * strings, error *correction* — use the codex32 (BIP-93) encoding (ShareCodeCodex32*).
 *
 * Encoding: "vcs1" || base32(ver || x || len || y[0..len) [|| mac[32]]) || 6-char bech32m checksum.
 * A single share of a 256-bit secret encodes to ~65 chars, well inside the 89-char guarantee window
 * (SHARECODE_BECH32M_MAX_CHARS). A share carrying its 32-byte MAC exceeds that window, so the 4-error
 * BCH guarantee no longer holds for it — that case is the codex32 default's job.
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
/* Written constant (D-2): the string length up to which bech32m's <=4-substitution BCH guarantee
   holds. A code longer than this still decodes, but the 4-error detection guarantee lapses — prefer
   the codex32 default there. A MAC-less 256-bit-secret share (~65 chars) stays within it. */
#define SHARECODE_BECH32M_MAX_CHARS  89

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

/* ---- codex32 (BIP-93): the default export encoding (decision D-2) ------------------------------------
 *
 * codex32 is a standard, *error-correcting* transcription envelope for a secret (or a share of one):
 *   "ms" || "1" || k || id[4] || shareIndex || bech32(payload) || ms32-checksum
 * where the ms32 checksum is a stronger BCH code than bech32m — 13 symbols for a short string, 15 for a
 * long one — designed to *correct* (not merely detect) transcription errors in a hand-copied share.
 * The "ms" HRP, the threshold digit k (0 or 2..9; 1 is invalid), the 4-char identifier, and the
 * one-char share index ('s' = the unshared secret) are all covered by the checksum.
 *
 * This carries an arbitrary `payload` (for the recovery kit, the bytes of a GF(2^8) ShamirShare — the
 * ms32 checksum/envelope is adopted for its error-correction; the underlying split stays this project's
 * GF(2^8) Shamir, NOT codex32's own GF(32) sharing, and encoding a raw seed at index 's'/k=0 is a
 * BIP-93-interoperable unshared secret). See docs/VSS-SPEC.md. */

#define SHARECODE_CODEX32_MAX_LEN   128   /* buffer for the "ms1..." string incl. NUL */

/* Encode `payload[0..payloadLen)` as a codex32 string. k is the threshold (0, or 2..9); id must be 4
   bech32 characters; shareIndex is one bech32 character ('s' for the unshared secret). Writes a
   NUL-terminated "ms1..." string to out[0..outCap). Returns SHARECODE_OK or a negative code. */
int ShareCodeCodex32Encode (int k, const char id[4], char shareIndex,
                            const unsigned char *payload, int payloadLen, char *out, int outCap);

/* Decode a codex32 "ms1..." string: verify the ms32 checksum, then fill *k, id[4], *shareIndex, and
   payload[0..*payloadLen). Returns SHARECODE_OK, SHARECODE_ERR_CHECKSUM (transcription error — reject),
   or SHARECODE_ERR_FORMAT. */
int ShareCodeCodex32Decode (const char *str, int *k, char id[4], char *shareIndex,
                            unsigned char *payload, int payloadCap, int *payloadLen);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_SHARECODE */

#endif /* TC_HEADER_Common_ShareCode */
