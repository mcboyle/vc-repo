/*
 * Shamir Secret Sharing over GF(2^8) (AES field, reduction polynomial 0x11B).
 *
 * Splits a secret into N shares such that any THRESHOLD of them reconstruct it and any fewer reveal
 * nothing. Each secret byte is an independent degree-(threshold-1) polynomial; shares are evaluated
 * at distinct nonzero x-coordinates and reconstruction is Lagrange interpolation at x = 0.
 *
 * Used by the VeraCrypt hardware-key-factor path to build a threshold / split-key factor: the
 * reconstructed secret is mixed into the password before PBKDF2 (see HardwareKeyFactor, RAW_SECRET
 * backend), so a volume can require e.g. 2-of-3 of {passphrase share, YubiKey share, recovery share}
 * with no header-format change. Standalone and dependency-free so it can be unit-tested in isolation.
 */

#ifndef TC_HEADER_Common_Shamir
#define TC_HEADER_Common_Shamir

#if defined(__cplusplus)
extern "C" {
#endif

#define SHAMIR_MAX_SHARES   16
#define SHAMIR_MAX_SECRET   64

/* One share: an x-coordinate (1..255, distinct per share) and one y-byte per secret byte. */
typedef struct
{
	unsigned char x;
	unsigned char y[SHAMIR_MAX_SECRET];
	int           len;              /* number of valid y bytes (== secret length) */
} ShamirShare;

/* Result codes (0 = OK, negative = error). */
#define SHAMIR_OK            0
#define SHAMIR_ERR_PARAM   (-1)

/*
 * Split 'secret' (secret_len bytes, 1..SHAMIR_MAX_SECRET) into n_shares, reconstructable by any
 * 'threshold' of them (2 <= threshold <= n_shares <= SHAMIR_MAX_SHARES).
 *
 * 'random_bytes' must supply (threshold-1)*secret_len cryptographically-random bytes (the non-constant
 * polynomial coefficients). Passing an explicit buffer keeps this deterministic for testing and forces
 * the caller to use a real CSPRNG in production. Shares are written to shares_out[0..n_shares-1] with
 * x = 1..n_shares. Returns SHAMIR_OK or a negative code.
 */
int shamir_split (const unsigned char *secret, int secret_len,
                  int threshold, int n_shares,
                  const unsigned char *random_bytes,
                  ShamirShare *shares_out);

/*
 * Reconstruct the secret from 'count' shares (count must be >= the threshold used at split time; all
 * shares must have the same len and distinct x). Writes secret_len bytes to secret_out. Returns
 * SHAMIR_OK or a negative code. Note: fewer than the true threshold, or wrong shares, yield an
 * incorrect secret (by design) rather than an error.
 */
int shamir_combine (const ShamirShare *shares, int count,
                    unsigned char *secret_out, int *secret_len_out);

/*
 * CRC-32 checksum of a secret, so a reconstruction can be *verified* rather than trusted blindly.
 * shamir_combine returns an incorrect secret (not an error) when given wrong or below-threshold shares;
 * compute this checksum at split time and keep it with the recovery kit (it reveals nothing about the
 * secret beyond a 32-bit fingerprint), then recompute it after shamir_combine and compare — a mistyped
 * share or an insufficient set is then detected instead of silently producing garbage. Detects
 * accidental corruption/transcription; for adversarial tamper-resistance use a keyed MAC instead.
 */
unsigned int shamir_secret_checksum (const unsigned char *secret, int len);

#if defined(__cplusplus)
}
#endif

#endif /* TC_HEADER_Common_Shamir */
